// ─── Authsignal Types ───────────────────────────────────────────────────────

export type VerificationMethod =
  | "SMS"
  | "EMAIL_OTP"
  | "EMAIL_MAGIC_LINK"
  | "AUTHENTICATOR_APP"
  | "PASSKEY"
  | "PUSH"
  | "WHATSAPP";

// ─── OIDC Bridge Types ──────────────────────────────────────────────────────

export interface OidcBridgeSession {
  state: string;
  codeVerifier: string;
  pingOneUserId: string;
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
  /** Which sign-in mode created the session. */
  provider: "davinci" | "pingone";
  email?: string;
  displayName?: string;
  mfaVerified: boolean;
  mfaMethod?: VerificationMethod;
  authenticatedAt: number;
  expiresAt: number;
}
