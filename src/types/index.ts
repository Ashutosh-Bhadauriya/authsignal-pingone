// ─── Authsignal Types ───────────────────────────────────────────────────────

export type AuthsignalActionState =
  | "ALLOW"
  | "BLOCK"
  | "CHALLENGE_REQUIRED"
  | "CHALLENGE_FAILED"
  | "CHALLENGE_SUCCEEDED"
  | "REVIEW_REQUIRED"
  | "REVIEW_FAILED"
  | "REVIEW_SUCCEEDED";

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
    phoneNumber?: string;
    ipAddress?: string;
    userAgent?: string;
    deviceId?: string;
    custom?: Record<string, unknown>;
    redirectToSettings?: boolean;
  };
}

export interface TrackActionResponse {
  state: AuthsignalActionState;
  idempotencyKey: string;
  url?: string;
  token?: string;
  isEnrolled: boolean;
  allowedVerificationMethods?: VerificationMethod[];
  enrolledVerificationMethods?: VerificationMethod[];
}

export interface ValidateChallengeResponse {
  isValid: boolean;
  state: AuthsignalActionState;
  stateUpdatedAt: string;
  userId: string;
  actionCode: string;
  idempotencyKey: string;
  verificationMethod?: VerificationMethod;
}

// ─── DaVinci Bridge Types ───────────────────────────────────────────────────

export interface DaVinciMfaInitRequest {
  userId: string;
  action?: string;
  email?: string;
  phoneNumber?: string;
  ipAddress?: string;
  userAgent?: string;
  redirectUrl: string;
  custom?: Record<string, unknown>;
}

export interface DaVinciMfaInitResponse {
  challengeRequired: boolean;
  state: AuthsignalActionState;
  challengeUrl?: string;
  token?: string;
  idempotencyKey: string;
  isEnrolled: boolean;
  enrolledMethods?: VerificationMethod[];
}

export interface DaVinciMfaVerifyRequest {
  token: string;
  userId: string;
  action: string;
}

export interface DaVinciMfaVerifyResponse {
  isValid: boolean;
  state: AuthsignalActionState;
  userId: string;
  action: string;
  verificationMethod?: VerificationMethod;
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

// ─── OIDC Provider Types ───────────────────────────────────────────────────

export interface OidcProviderSession {
  internalState: string;
  internalNonce: string;
  authsignalCodeVerifier: string;
  authsignalRedirectUri: string;
  davinciRedirectUri: string;
  davinciState: string;
  davinciNonce?: string;
  davinciClientId: string;
  davinciCodeChallenge?: string;
  davinciCodeChallengeMethod?: string;
  userId: string;
  action: string;
  email?: string;
  createdAt: number;
}

export interface OidcProviderAuthorizationCode {
  code: string;
  userId: string;
  action: string;
  actionState: string;
  verificationMethod?: string;
  davinciRedirectUri: string;
  davinciClientId: string;
  davinciNonce?: string;
  davinciCodeChallenge?: string;
  davinciCodeChallengeMethod?: string;
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
