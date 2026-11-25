#!/usr/bin/env python3
"""Builds a DaVinci flow that adds Authsignal MFA to Ping's sign-on template.

Inputs (both exported from DaVinci with "Download Flow JSON", variable values off):

  exports/pingone-signon-template.json     Ping's "PingOne Sign On with Registration,
                                           Password Reset and Recovery" template
  exports/authsignal-flows-mfa-oidc.json   A flow containing one configured Sign On node
                                           of the "OIDC & OAuth IdP" connector that
                                           points at the bridge

The template ends its sign-on path in a "Sign On Success" section that receives the
PingOne user ID. This script inserts the Authsignal Sign On node at the start of that
section, passes the PingOne user ID as login_hint, and sends a failed or abandoned
challenge to an error page instead of the success response.

Outputs:

  exports/pingone-signon-authsignal-mfa.import.json   importable into the same environment
  pingone-signon-authsignal-mfa.template.json         same flow with IDs replaced by placeholders

Usage: python3 -I davinci/build_flow.py
"""

from __future__ import annotations

import copy
import json
import pathlib
import random
import string

HERE = pathlib.Path(__file__).resolve().parent
TEMPLATE = HERE / "exports" / "pingone-signon-template.json"
OIDC_FLOW = HERE / "exports" / "authsignal-flows-mfa-oidc.json"
OUT_IMPORT = HERE / "exports" / "pingone-signon-authsignal-mfa.import.json"
OUT_TEMPLATE = HERE / "pingone-signon-authsignal-mfa.template.json"

FLOW_NAME = "PingOne Sign On + Authsignal MFA"
FLOW_DESCRIPTION = (
    "Ping's sign-on template with an Authsignal MFA step after the password check. "
    "The step redirects to Authsignal through the OIDC & OAuth IdP connector and runs an Authsignal Flow."
)
SUCCESS_START_TITLE = "Sign On Success"

# Deterministic IDs so rebuilding the flow gives the same file.
rng = random.Random("authsignal-pingone-davinci")


def new_id(length: int = 10) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def rich_text(text: str) -> str:
    """DaVinci stores text fields as a JSON string in Slate format."""
    return json.dumps([{"children": [{"text": text}]}], indent=2)


def rich_variable(label: str, reference: str, icon: str) -> str:
    return json.dumps(
        [
            {
                "children": [
                    {"text": ""},
                    {
                        "type": "link",
                        "src": icon,
                        "url": label,
                        "data": reference,
                        "tooltip": reference,
                        "children": [{"text": label}],
                    },
                    {"text": ""},
                ]
            }
        ],
        indent=2,
    )


def wrap(like: dict, data: dict, position: dict | None = None) -> dict:
    """Wraps node or edge data in the same envelope an existing element uses."""
    element = {key: copy.deepcopy(value) for key, value in like.items() if key not in ("data", "position")}
    element["data"] = data
    if position is not None:
        element["position"] = position
    elif "position" in like:
        element["position"] = copy.deepcopy(like["position"])
    element["selected"] = False
    return element


def title_of(node: dict) -> str:
    value = node["data"].get("properties", {}).get("nodeTitle", {})
    return value.get("value", "") if isinstance(value, dict) else ""


def build() -> dict:
    flow = json.loads(TEMPLATE.read_text())
    oidc_flow = json.loads(OIDC_FLOW.read_text())

    elements = flow["graphData"]["elements"]
    nodes, edges = elements["nodes"], elements["edges"]
    by_id = {node["data"]["id"]: node for node in nodes}

    # ── Locate the splice point: Sign On Success start → EVAL → success response ──
    start = next(
        node
        for node in nodes
        if node["data"].get("capabilityName") == "startNode" and title_of(node) == SUCCESS_START_TITLE
    )
    start_id = start["data"]["id"]
    start_edge = next(edge for edge in edges if edge["data"]["source"] == start_id)
    first_eval_id = start_edge["data"]["target"]
    eval_to_success = next(edge for edge in edges if edge["data"]["source"] == first_eval_id)
    success = by_id[eval_to_success["data"]["target"]]
    if success["data"].get("capabilityName") != "createSuccessResponse":
        raise SystemExit("Template changed: Sign On Success no longer leads straight to the success response")

    user_id_reference = f"{{{{local.{start_id}.payload.output.p1UserId}}}}"

    # ── Authsignal Sign On node, copied from the configured connector node ──
    oidc_source = next(
        node
        for node in oidc_flow["graphData"]["elements"]["nodes"]
        if node["data"].get("connectorId") == "genericConnector"
        and node["data"].get("capabilityName") == "loginFirstFactor"
    )
    oidc_id = new_id()
    oidc_data = copy.deepcopy(oidc_source["data"])
    oidc_data["id"] = oidc_id
    oidc_data["properties"]["customAuth"]["properties"]["queryParams"]["value"] = [
        {
            "key": rich_text("login_hint"),
            "value": rich_variable("p1UserId", user_id_reference, "teleport.svg"),
        }
    ]
    oidc_data["properties"]["skipButtonPress"] = {"value": True}
    oidc_data["properties"]["nodeTitle"] = {"value": "Authsignal MFA"}
    oidc_data["properties"]["nodeDescription"] = {
        "value": "Redirects to Authsignal with the PingOne user ID as login_hint and waits for the result"
    }

    # ── Error page for a failed or abandoned challenge ──
    error_source = next(node for node in nodes if node["data"].get("connectorId") == "errorConnector")
    error_id = new_id()
    error_data = copy.deepcopy(error_source["data"])
    error_data["id"] = error_id
    error_data["idUnique"] = new_id()
    error_data["properties"] = {
        "errorMessage": {"value": rich_text("Verification was not completed")},
        "errorDescription": {"value": rich_text("The second factor with Authsignal failed or was cancelled. Sign in again to retry.")},
        "errorCode": {"value": rich_text("authsignal_mfa_failed")},
        "errorReason": {"value": rich_text("Authsignal did not confirm the challenge")},
        "nodeTitle": {"value": "Authsignal MFA failed"},
        "nodeDescription": {"value": "The Authsignal challenge failed, was cancelled or timed out"},
    }

    # ── Branch after the Authsignal node: true → success, false → error page ──
    branch_id = new_id()
    branch_data = {
        "id": branch_id,
        "nodeType": "EVAL",
        "label": "Evaluator",
        "properties": {error_id: {"value": "anyTriggersFalse"}},
    }

    # ── Record the second factor in the success response ──
    for claim in success["data"]["properties"]["claimsNameValuePairs"]["value"]:
        if claim.get("name") == "authMethod":
            claim["value"] = rich_text("mfa")

    # ── Layout: keep the row, push the success node right to make room ──
    row_y = success["position"]["y"]
    oidc_x = success["position"]["x"]
    success["position"] = {"x": oidc_x + 480, "y": row_y}

    eval_like = by_id[first_eval_id]
    nodes.extend(
        [
            wrap(oidc_source, oidc_data, {"x": oidc_x, "y": row_y}),
            wrap(eval_like, branch_data, {"x": oidc_x + 240, "y": row_y}),
            wrap(error_source, error_data, {"x": oidc_x + 480, "y": row_y + 200}),
        ]
    )

    success_id = success["data"]["id"]
    eval_to_success["data"]["target"] = oidc_id
    edge_like = eval_to_success
    for source, target in ((oidc_id, branch_id), (branch_id, success_id), (branch_id, error_id)):
        edges.append(wrap(edge_like, {"id": new_id(), "source": source, "target": target}))

    # ── Flow metadata ──
    flow["name"] = FLOW_NAME
    flow["description"] = FLOW_DESCRIPTION
    if "genericConnector" not in flow["connectorIds"]:
        flow["connectorIds"].append("genericConnector")
    for key in ("flowId", "versionId", "currentVersion", "publishedVersion", "createdDate", "updatedDate", "savedDate", "deployedDate"):
        flow.pop(key, None)

    return flow, oidc_data["connectionId"]


def to_template(flow: dict, oidc_connection_id: str) -> dict:
    """Replaces environment-specific IDs so the file is safe to share."""
    text = json.dumps(flow)
    text = text.replace(oidc_connection_id, "{{AUTHSIGNAL_OIDC_CONNECTION_ID}}")
    for key in ("companyId", "customerId"):
        value = flow.get(key)
        if isinstance(value, str) and value:
            text = text.replace(value, "{{YOUR_PINGONE_" + ("ENVIRONMENT" if key == "companyId" else "CUSTOMER") + "_ID}}")
    return json.loads(text)


def main() -> None:
    flow, oidc_connection_id = build()
    OUT_IMPORT.write_text(json.dumps(flow, indent=2) + "\n")
    OUT_TEMPLATE.write_text(json.dumps(to_template(flow, oidc_connection_id), indent=2) + "\n")
    counts = flow["graphData"]["elements"]
    print(f"nodes={len(counts['nodes'])} edges={len(counts['edges'])}")
    print(f"wrote {OUT_IMPORT.relative_to(HERE.parent)}")
    print(f"wrote {OUT_TEMPLATE.relative_to(HERE.parent)}")


if __name__ == "__main__":
    main()
