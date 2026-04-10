import { config } from "../config.js";
import * as jose from "jose";
import { verifyPingOneIdToken } from "../utils/jwt.js";

// ─── Token Validation ───────────────────────────────────────────────────────

export async function verifyIdToken(
  idToken: string,
  nonce?: string
): Promise<jose.JWTPayload> {
  return verifyPingOneIdToken(
    idToken,
    config.pingone.authBaseUrl,
    config.pingone.environmentId,
    config.pingone.clientId,
    nonce
  );
}

// ─── Authorization URL Builder ──────────────────────────────────────────────

export function buildAuthorizeUrl(params: {
  redirectUri: string;
  state: string;
  nonce: string;
  codeChallenge: string;
}): string {
  const { environmentId, clientId, authBaseUrl } = config.pingone;
  const url = new URL(`/${environmentId}/as/authorize`, authBaseUrl);

  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("scope", "openid profile email");
  url.searchParams.set("state", params.state);
  url.searchParams.set("nonce", params.nonce);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  return url.toString();
}

// ─── Token Exchange ─────────────────────────────────────────────────────────

interface PingOneTokenResponse {
  access_token: string;
  id_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
}

export async function exchangeCode(params: {
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<PingOneTokenResponse> {
  const { environmentId, clientId, clientSecret, authBaseUrl } = config.pingone;
  const tokenUrl = `${authBaseUrl}/${environmentId}/as/token`;

  // PingOne uses Client Secret Basic auth (credentials in Authorization header)
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
    }).toString(),
  });

  if (!response.ok) {
    throw new Error(`PingOne token exchange failed with status ${response.status}`);
  }

  return response.json() as Promise<PingOneTokenResponse>;
}
