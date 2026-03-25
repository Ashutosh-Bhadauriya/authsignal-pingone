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

// ─── PingOne Types ──────────────────────────────────────────────────────────

export interface PingOneTokenPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time?: number;
  at_hash?: string;
  acr?: string;
  amr?: string[];
  env: string;
  org: string;
  "p1.region"?: string;
}

export interface PingOneUser {
  id: string;
  environment: { id: string };
  username: string;
  email?: string;
  name?: {
    given?: string;
    family?: string;
  };
  phone?: string;
  mfaEnabled?: boolean;
}

export type PingOneFlowStatus =
  | "USERNAME_PASSWORD_REQUIRED"
  | "PASSWORD_REQUIRED"
  | "DEVICE_SELECTION_REQUIRED"
  | "OTP_REQUIRED"
  | "PUSH_CONFIRMATION_REQUIRED"
  | "EXTERNAL_AUTHENTICATION_REQUIRED"
  | "COMPLETED"
  | "FAILED";

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
