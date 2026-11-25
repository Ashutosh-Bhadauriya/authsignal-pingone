import { Authsignal, VerificationMethod as AuthsignalVerificationMethod } from "@authsignal/node";
import { config } from "../config.js";

// ─── Server SDK Client ──────────────────────────────────────────────────────

const authsignal = new Authsignal({
  apiSecretKey: config.authsignal.secret,
  apiUrl: config.authsignal.apiUrl,
});

// ─── Manage Settings URL ────────────────────────────────────────────────────
// Returns the URL to Authsignal's authenticator management UI for a user.

export async function getManageSettingsUrl(params: {
  userId: string;
  email?: string;
  redirectUrl: string;
}): Promise<string | undefined> {
  const result = await authsignal.track({
    userId: params.userId,
    action: "manageSettings",
    attributes: {
      email: params.email,
      redirectUrl: params.redirectUrl,
      redirectToSettings: true,
    },
  });

  return result.url;
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

interface AuthsignalTokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
}

export async function oidcTokenExchange(params: {
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<AuthsignalTokenResponse> {
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

  return response.json() as Promise<AuthsignalTokenResponse>;
}

// ─── Flows ──────────────────────────────────────────────────────────────────
// Start and verify an Authsignal Flow (action type FLOW). Flows replace the
// classic track/validate pair: `POST /flows` returns a hosted-UI URL, and
// `POST /flows/verify` consumes the single-use challenge token the hosted UI
// appends to the redirect URL.

const FLOWS_TIMEOUT_MS = 10_000;

function basicAuthHeader(): string {
  return `Basic ${Buffer.from(`${config.authsignal.secret}:`).toString("base64")}`;
}

export type FlowState =
  | "CHALLENGE_REQUIRED"
  | "CHALLENGE_SUCCEEDED"
  | "CHALLENGE_FAILED";

export interface FlowStep {
  stepType?: string;
  verificationMethod?: string;
  userAuthenticatorId?: string;
}

export interface StartFlowResponse {
  challengeId: string;
  challengeToken: string;
  challengeUrl: string;
  action: { state: FlowState; completedSteps?: FlowStep[] };
}

export interface VerifyFlowResponse {
  challengeId: string;
  action: { state: FlowState; completedSteps?: FlowStep[] };
  user?: { userId?: string };
}

export class AuthsignalApiError extends Error {
  constructor(
    readonly operation: string,
    readonly status: number
  ) {
    super(`Authsignal ${operation} failed with status ${status}`);
  }
}

async function flowsRequest<T>(
  operation: string,
  path: string,
  body: unknown
): Promise<T> {
  const response = await fetch(`${config.authsignal.apiUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: basicAuthHeader(),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(FLOWS_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new AuthsignalApiError(operation, response.status);
  }

  return response.json() as Promise<T>;
}

export async function startFlow(params: {
  actionCode: string;
  userId: string;
  redirectUrl: string;
  ipAddress?: string;
  userAgent?: string;
}): Promise<StartFlowResponse> {
  const attributes =
    params.ipAddress || params.userAgent
      ? { ipAddress: params.ipAddress, userAgent: params.userAgent }
      : undefined;

  return flowsRequest<StartFlowResponse>("start flow", "/flows", {
    actionCode: params.actionCode,
    user: { userId: params.userId },
    redirectUrl: params.redirectUrl,
    attributes,
  });
}

export async function verifyFlow(params: {
  actionCode: string;
  challengeToken: string;
}): Promise<VerifyFlowResponse> {
  return flowsRequest<VerifyFlowResponse>("verify flow", "/flows/verify", {
    actionCode: params.actionCode,
    challengeToken: params.challengeToken,
  });
}
