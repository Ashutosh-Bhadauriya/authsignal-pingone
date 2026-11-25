#!/usr/bin/env python3
"""Builds a small DaVinci flow for passwordless sign-in with Authsignal.

    username form  ->  Authsignal Sign On (login_hint = username)  ->  success response
                                                                \\->  error page

The success response carries the username in its additional properties. The
demo app launches this flow with the DaVinci widget and expects two settings
this script does not write, because their JSON shape is not in the exports it
builds from. Set them in DaVinci after importing (see the README, "Demo app"):

  - Signed Response on the final Send Success JSON Response node
  - a required String input parameter named "nonce" in the flow's Input Schema

There is no password step: Authsignal is the only factor, so this is NOT an MFA
setup. Anyone who enters a username can enrol it. Use it for demos and for
environments without a user directory. For MFA after a PingOne password, use
build_flow.py.

Inputs are the same two exports build_flow.py uses (see that file). The sign-on
template is only used as a source of node envelopes, the form markup conventions
and the flow settings.

Outputs:

  exports/authsignal-passwordless.import.json   importable into the same environment
  authsignal-passwordless.template.json         same flow with IDs replaced by placeholders

Usage: python3 -I davinci/build_passwordless_flow.py
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from build_flow import OIDC_FLOW, TEMPLATE, new_id, rich_text, rich_variable, to_template, wrap  # noqa: E402

OUT_IMPORT = HERE / "exports" / "authsignal-passwordless.import.json"
OUT_TEMPLATE = HERE / "authsignal-passwordless.template.json"

FLOW_NAME = "Authsignal Passwordless Sign-In (OIDC)"
FLOW_DESCRIPTION = (
    "Asks for a username, then redirects to Authsignal through the OIDC & OAuth IdP connector. "
    "Authsignal is the only factor: there is no password step, so this is not an MFA flow."
)

FORM_HTML = """<div class="end-user-nano">
  <div
    class="bg-light d-flex flex-column justify-content-center align-items-center position-absolute top-0 start-0 bottom-0 end-0 overflow-auto">
    <div style="max-width: 400px; min-width: 400px; width: 100%">
      <div class="card shadow mb-2">
        <main aria-labelledby="title">
          <div class="card-body p-5 d-flex flex-column">
            {{#if title}}
            <h1 id="title" class="text-center mb-4">{{title}}</h1>
            {{/if}}

            {{#if textOne}}
            <p class="text-muted text-center">{{textOne}}</p>
            {{/if}}

            <p class="text-danger mdi mdi-alert-circle text-center icon-padding" id="feedbackError" data-id="feedback"
              data-skcomponent="skerror" aria-live="assertive"></p>

            <form id="signonForm" aria-labelledby="title" data-id="signonForm">
              <div class="mb-4 form-floating">
                <input class="form-control" id="username" name="username" placeholder="Username or email"
                  autocomplete="username" data-id="username-input" aria-required="true" required
                  pattern="[A-Za-z0-9_.@+\\-]{1,128}" aria-describedby="usernameLabel" />
                <label id="usernameLabel" for="username">Username or email</label>
              </div>
              <div class="d-flex flex-column">
                <button data-id="button" type="submit" class="btn btn-primary mb-3" data-skcomponent="skbutton"
                  data-skbuttontype="form-submit" id="btnSignIn" data-skform="signonForm"
                  data-skbuttonvalue="SIGNON">
                  Continue with Authsignal
                </button>
              </div>
            </form>
          </div>
        </main>
      </div>
    </div>
  </div>
</div>"""

FORM_SCRIPT = """const start = () => {
    const element = document.getElementById("username");
    if (element) {
        element.focus();
    }
};

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
} else {
    start();
}"""


def title_of(node: dict) -> str:
    value = node["data"].get("properties", {}).get("nodeTitle", {})
    return value.get("value", "") if isinstance(value, dict) else ""


def build() -> tuple[dict, str]:
    template = json.loads(TEMPLATE.read_text())
    oidc_flow = json.loads(OIDC_FLOW.read_text())
    template_nodes = template["graphData"]["elements"]["nodes"]
    template_edges = template["graphData"]["elements"]["edges"]

    form_source = next(
        node
        for node in template_nodes
        if node["data"].get("capabilityName") == "customHTMLTemplate" and title_of(node) == "Sign On"
    )
    error_source = next(node for node in template_nodes if node["data"].get("connectorId") == "errorConnector")
    eval_source = next(node for node in template_nodes if node["data"].get("nodeType") == "EVAL")
    oidc_nodes = oidc_flow["graphData"]["elements"]["nodes"]
    oidc_source = next(node for node in oidc_nodes if node["data"].get("connectorId") == "genericConnector")
    success_source = next(
        node for node in template_nodes if node["data"].get("capabilityName") == "createSuccessResponse"
    )

    form_id, oidc_id, branch_id, first_eval_id, success_id, error_id = (new_id() for _ in range(6))
    username_reference = f"{{{{local.{form_id}.payload.output.username}}}}"

    # ── 1. Username form ──
    form = copy.deepcopy(form_source["data"])
    form["id"] = form_id
    form.pop("isDisabled", None)
    form["properties"].update(
        {
            "title": {"value": rich_text("Sign in")},
            "textOne": {"value": rich_text("Enter your username to continue with Authsignal")},
            "customHTML": {"value": FORM_HTML},
            "customScript": {"value": FORM_SCRIPT},
            "formFieldsList": {
                "value": [
                    {
                        "preferredControlType": "textField",
                        "preferredDataType": "string",
                        "propertyName": "username",
                        "displayName": "Username",
                        "hashedVisibility": False,
                        "value": rich_text(""),
                    },
                    {"preferredControlType": "textField", "preferredDataType": "string", "propertyName": "buttonValue"},
                ]
            },
            "nodeTitle": {"value": "Username"},
            "nodeDescription": {"value": "Asks who is signing in. No password is collected."},
        }
    )

    # ── 2. Authsignal Sign On ──
    oidc = copy.deepcopy(oidc_source["data"])
    oidc["id"] = oidc_id
    oidc["properties"]["customAuth"]["properties"]["queryParams"]["value"] = [
        {"key": rich_text("login_hint"), "value": rich_variable("username", username_reference, "http.svg")}
    ]
    oidc["properties"]["skipButtonPress"] = {"value": True}
    oidc["properties"]["nodeTitle"] = {"value": "Authsignal sign-in"}
    oidc["properties"]["nodeDescription"] = {
        "value": "Redirects to Authsignal with the username as login_hint and waits for the result"
    }

    # ── 3. Results ──
    success = copy.deepcopy(success_source["data"])
    success["id"] = success_id
    success["idUnique"] = new_id()
    success["properties"] = {
        "nodeTitle": {"value": "Signed in"},
        "nodeDescription": {"value": "Ends the flow and returns the username to the application."},
        "backgroundColor": success_source["data"]["properties"].get("backgroundColor", {"value": "#9dc967ff"}),
        "claimsNameValuePairs": {
            "value": [
                {
                    "name": "username",
                    "value": rich_variable("username", username_reference, "http.svg"),
                    "key": 0.4127193846520317,
                    "label": "username (string - flowInstance)",
                    "type": "string",
                    "nameDefault": "username",
                }
            ]
        },
        "oeInteractionCacheExpire": {"value": True},
    }

    error = copy.deepcopy(error_source["data"])
    error["id"] = error_id
    error["idUnique"] = new_id()
    error["properties"] = {
        "errorMessage": {"value": rich_text("Sign-in was not completed")},
        "errorDescription": {"value": rich_text("Authsignal did not confirm the sign-in. Start again to retry.")},
        "errorCode": {"value": rich_text("authsignal_signin_failed")},
        "errorReason": {"value": rich_text("Authsignal did not confirm the challenge")},
        "nodeTitle": {"value": "Authsignal sign-in failed"},
        "nodeDescription": {"value": "The Authsignal challenge failed, was cancelled or timed out"},
    }

    first_eval = {"id": first_eval_id, "nodeType": "EVAL"}
    branch = {
        "id": branch_id,
        "nodeType": "EVAL",
        "label": "Evaluator",
        "properties": {error_id: {"value": "anyTriggersFalse"}},
    }

    y = 400
    nodes = [
        wrap(form_source, form, {"x": 300, "y": y}),
        wrap(eval_source, first_eval, {"x": 500, "y": y}),
        wrap(oidc_source, oidc, {"x": 700, "y": y}),
        wrap(eval_source, branch, {"x": 900, "y": y}),
        wrap(success_source, success, {"x": 1120, "y": y}),
        wrap(error_source, error, {"x": 1120, "y": y + 200}),
    ]
    edge_like = template_edges[0]
    edges = [
        wrap(edge_like, {"id": new_id(), "source": source, "target": target})
        for source, target in (
            (form_id, first_eval_id),
            (first_eval_id, oidc_id),
            (oidc_id, branch_id),
            (branch_id, success_id),
            (branch_id, error_id),
        )
    ]

    # ── Flow shell: keep the template's settings (stylesheets for the form), drop its content ──
    flow = copy.deepcopy(template)
    flow["graphData"]["elements"] = {"nodes": nodes, "edges": edges}
    flow["name"] = FLOW_NAME
    flow["description"] = FLOW_DESCRIPTION
    flow["connectorIds"] = ["httpConnector", "genericConnector", "errorConnector"]
    flow["variables"] = []
    flow["inputSchema"] = []
    flow.pop("inputSchemaCompiled", None)
    flow["isInputSchemaSaved"] = False
    for key in ("flowId", "versionId", "currentVersion", "publishedVersion", "createdDate", "updatedDate", "savedDate", "deployedDate"):
        flow.pop(key, None)

    return flow, oidc["connectionId"]


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
