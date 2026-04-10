import { Authsignal, VerificationMethod as AuthsignalVerificationMethod } from "@authsignal/node";
import { config } from "../config.js";
import type { TrackActionRequest, TrackActionResponse } from "../types/index.js";

// ─── Server SDK Client ──────────────────────────────────────────────────────

const authsignal = new Authsignal({
  apiSecretKey: config.authsignal.secret,
  apiUrl: config.authsignal.apiUrl,
});

// ─── Track Action ───────────────────────────────────────────────────────────

export async function trackAction(
  req: TrackActionRequest
): Promise<TrackActionResponse> {
  const result = await authsignal.track({
    userId: req.userId,
    action: req.action,
    attributes: {
      redirectUrl: req.attributes?.redirectUrl,
      email: req.attributes?.email,
      redirectToSettings: req.attributes?.redirectToSettings,
    },
  });

  return { url: result.url };
}

// ─── Get User Enrollment ────────────────────────────────────────────────────

export async function getUser(userId: string) {
  return authsignal.getUser({ userId });
}

// ─── Enroll Verified Authenticator ──────────────────────────────────────────
// Enroll a pre-verified authenticator for a user (e.g., email from PingOne).

export async function enrollVerifiedAuthenticator(params: {
  userId: string;
  verificationMethod: AuthsignalVerificationMethod;
  email?: string;
  isDefault?: boolean;
}) {
  return authsignal.enrollVerifiedAuthenticator({
    userId: params.userId,
    attributes: {
      verificationMethod: params.verificationMethod,
      email: params.email,
      isDefault: params.isDefault,
    },
  });
}

export { AuthsignalVerificationMethod };

// ─── OIDC Init Auth ─────────────────────────────────────────────────────────
// Calls Authsignal's OIDC /init-auth endpoint to get a short-lived token
// that can be used in the OIDC authorization redirect.

export async function oidcInitAuth(params: {
  userId: string;
  action: string;
  email?: string;
  phoneNumber?: string;
}): Promise<{ token: string }> {
  const basicAuth = Buffer.from(`${config.authsignal.secret}:`).toString(
    "base64"
  );

  const response = await fetch(`${config.authsignal.oidcUrl}/init-auth`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${basicAuth}`,
    },
    body: JSON.stringify({
      userId: params.userId,
      action: params.action,
      email: params.email,
      phoneNumber: params.phoneNumber,
    }),
  });

  if (!response.ok) {
    throw new Error(
      `Authsignal OIDC init-auth failed with status ${response.status}`
    );
  }

  return response.json() as Promise<{ token: string }>;
}

// ─── OIDC Token Exchange ────────────────────────────────────────────────────
// Exchanges an authorization code at Authsignal's OIDC token endpoint.

export async function oidcTokenExchange(params: {
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<{
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
}> {
  // Discovery doc specifies client_secret_post (credentials in POST body, not Basic auth)
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: params.redirectUri,
    code_verifier: params.codeVerifier,
    client_id: config.authsignal.tenantId,
    client_secret: config.authsignal.secret,
  });

  const response = await fetch(`${config.authsignal.oidcUrl}/oidc/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
  });

  if (!response.ok) {
    throw new Error(
      `Authsignal OIDC token exchange failed with status ${response.status}`
    );
  }

  return response.json() as Promise<any>;
}
