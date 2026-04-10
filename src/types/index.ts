// ─── Authsignal Types ───────────────────────────────────────────────────────

export type VerificationMethod =
  | "SMS"
  | "EMAIL_OTP"
  | "EMAIL_MAGIC_LINK"
  | "AUTHENTICATOR_APP"
  | "PASSKEY"
  | "PUSH"
  | "WHATSAPP";

export interface TrackActionRequest {
  userId: string;
  action: string;
  attributes?: {
    redirectUrl?: string;
    email?: string;
    redirectToSettings?: boolean;
  };
}

export interface TrackActionResponse {
  url?: string;
}

// ─── OIDC Bridge Types ──────────────────────────────────────────────────────

export interface OidcBridgeSession {
  state: string;
  nonce: string;
  codeVerifier: string;
  pingOneUserId: string;
  pingOneSessionId?: string;
  callbackUrl?: string;
  callbackState?: string;
  action: string;
  redirectUri: string;
  createdAt: number;
}

// ─── Session Types ──────────────────────────────────────────────────────────

export interface AppSession {
  userId: string;
  pingOneUserId: string;
  email?: string;
  displayName?: string;
  mfaVerified: boolean;
  mfaMethod?: VerificationMethod;
  authenticatedAt: number;
  expiresAt: number;
}
