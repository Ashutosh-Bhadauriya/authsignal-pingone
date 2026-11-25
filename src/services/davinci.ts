/**
 * DaVinci for the demo app, using the embedded widget.
 *
 * A DaVinci Application can only send the browser back to an app by redirect
 * when the app is also registered in PingOne. The widget needs nothing but the
 * DaVinci Application: this server trades the application's API key for a
 * short-lived SDK token, the page renders the flow with davinci.js, and the
 * flow's success response comes back to the page's callback.
 */

import * as jose from "jose";
import { config } from "../config.js";

function settings() {
  const { issuer, sdkTokenUrl, apiKey, policyId, environmentId } = config.davinci;
  if (!issuer || !sdkTokenUrl || !apiKey || !policyId || !environmentId) {
    throw new Error("DaVinci is not configured");
  }
  return { issuer, sdkTokenUrl, apiKey, policyId, environmentId };
}

/**
 * Gets an SDK token for the widget. The API key stays on the server.
 */
export async function getSdkToken(): Promise<string> {
  const { sdkTokenUrl, apiKey } = settings();
  const response = await fetch(sdkTokenUrl, {
    method: "GET",
    headers: { "X-SK-API-KEY": apiKey, Accept: "application/json" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`DaVinci SDK token request failed with status ${response.status}`);
  }
  const body = (await response.json()) as { access_token?: string; success?: boolean };
  if (!body.access_token) {
    throw new Error("DaVinci returned no SDK token");
  }
  return body.access_token;
}

let jwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;

/**
 * Verifies a JWT signed with the environment's DaVinci keys.
 */
export async function verifyDavinciJwt(token: string): Promise<jose.JWTPayload> {
  const { issuer } = settings();
  if (!jwks) {
    jwks = jose.createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
  }
  const { payload } = await jose.jwtVerify(token, jwks, {
    algorithms: ["RS256"],
    clockTolerance: 30,
    requiredClaims: ["exp"],
  });
  return payload;
}
