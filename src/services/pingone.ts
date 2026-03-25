import { config } from "../config.js";
import * as jose from "jose";
import { verifyPingOneIdToken } from "../utils/jwt.js";
import type { PingOneUser } from "../types/index.js";

// ─── Token Cache ────────────────────────────────────────────────────────────

let managementToken: { token: string; expiresAt: number } | null = null;

async function getManagementToken(): Promise<string> {
  if (managementToken && managementToken.expiresAt > Date.now() + 30_000) {
    return managementToken.token;
  }

  const { environmentId, clientId, clientSecret, authBaseUrl } = config.pingone;
  const tokenUrl = `${authBaseUrl}/${environmentId}/as/token`;

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
    }).toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`PingOne token request failed: ${response.status} ${text}`);
  }

  const data = (await response.json()) as {
    access_token: string;
    expires_in: number;
  };

  managementToken = {
    token: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  };

  return data.access_token;
}

// ─── User Management ────────────────────────────────────────────────────────

export async function getUser(userId: string): Promise<PingOneUser> {
  const token = await getManagementToken();
  const { environmentId, apiBaseUrl } = config.pingone;

  const response = await fetch(
    `${apiBaseUrl}/environments/${environmentId}/users/${userId}`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`PingOne get user failed: ${response.status} ${text}`);
  }

  return response.json() as Promise<PingOneUser>;
}

export async function getUserByEmail(email: string): Promise<PingOneUser | null> {
  const token = await getManagementToken();
  const { environmentId, apiBaseUrl } = config.pingone;

  const filter = encodeURIComponent(`email eq "${email}"`);
  const response = await fetch(
    `${apiBaseUrl}/environments/${environmentId}/users?filter=${filter}`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );

  if (!response.ok) return null;

  const data = (await response.json()) as {
    _embedded?: { users?: PingOneUser[] };
  };
  return data._embedded?.users?.[0] ?? null;
}

// ─── Token Validation ───────────────────────────────────────────────────────

export async function verifyIdToken(
  idToken: string
): Promise<jose.JWTPayload> {
  return verifyPingOneIdToken(
    idToken,
    config.pingone.authBaseUrl,
    config.pingone.environmentId,
    config.pingone.clientId
  );
}

// ─── Authorization URL Builder ──────────────────────────────────────────────

export function buildAuthorizeUrl(params: {
  redirectUri: string;
  state: string;
  nonce: string;
  codeChallenge: string;
  scope?: string;
  acrValues?: string;
  loginHint?: string;
}): string {
  const { environmentId, clientId, authBaseUrl } = config.pingone;
  const url = new URL(`/${environmentId}/as/authorize`, authBaseUrl);

  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("scope", params.scope ?? "openid profile email");
  url.searchParams.set("state", params.state);
  url.searchParams.set("nonce", params.nonce);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  if (params.acrValues) {
    url.searchParams.set("acr_values", params.acrValues);
  }
  if (params.loginHint) {
    url.searchParams.set("login_hint", params.loginHint);
  }

  return url.toString();
}

// ─── Token Exchange ─────────────────────────────────────────────────────────

export async function exchangeCode(params: {
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<{
  access_token: string;
  id_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
}> {
  const { environmentId, clientId, clientSecret, authBaseUrl } = config.pingone;
  const tokenUrl = `${authBaseUrl}/${environmentId}/as/token`;

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
      client_id: clientId,
      client_secret: clientSecret,
    }).toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`PingOne token exchange failed: ${response.status} ${text}`);
  }

  return response.json() as Promise<any>;
}

// ─── Resume Authorization Flow ──────────────────────────────────────────────

export function buildResumeUrl(flowId: string): string {
  const { environmentId, authBaseUrl } = config.pingone;
  return `${authBaseUrl}/${environmentId}/as/resume?flowId=${flowId}`;
}
