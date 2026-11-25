/**
 * OIDC Provider Routes
 *
 * Exposes the bridge as a standard OpenID Connect provider (authorization code
 * flow) so that it can be added to:
 *
 * - PingOne, as an External Identity Provider used as a second step in an
 *   authentication policy (with "Pass user context to provider" enabled).
 * - PingOne DaVinci, through its generic OIDC connector.
 *
 * The MFA step itself is an Authsignal Flow:
 *
 * 1. PingOne  → GET  /oidc-provider/authorize?login_hint=<user>&state=...
 * 2. Bridge   → POST Authsignal /v1/flows            (start the flow for that user)
 * 3. Browser  → Authsignal hosted UI                 (user completes the flow)
 * 4. Browser  → GET  /oidc-provider/callback?state=...&challenge_token=...
 * 5. Bridge   → POST Authsignal /v1/flows/verify     (single-use, server-side)
 * 6. Browser  → PingOne redirect_uri?code=...&state=...
 * 7. PingOne  → POST /oidc-provider/token            (code → signed ID token)
 */

import { randomBytes } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { config } from "../config.js";
import {
  AuthsignalApiError,
  startFlow,
  verifyFlow,
} from "../services/authsignal.js";
import {
  ID_TOKEN_TTL_SECONDS,
  getJwks,
  signIdToken,
} from "../services/signing-keys.js";
import {
  generateCodeChallenge,
  generateState,
  timingSafeEqualStrings,
} from "../utils/crypto.js";
import { getQueryString } from "../utils/validation.js";

const router = Router();

// ─── Stores (in memory; use Redis or similar when running more than one instance) ──

interface ProviderSession {
  userId: string;
  clientId: string;
  redirectUri: string;
  state: string;
  nonce?: string;
  codeChallenge?: string;
  requestedAcr?: string;
  createdAt: number;
}

interface AuthorizationCode {
  userId: string;
  clientId: string;
  redirectUri: string;
  nonce?: string;
  codeChallenge?: string;
  acr?: string;
  verificationMethods: string[];
  authTime: number;
  createdAt: number;
}

interface AccessToken {
  userId: string;
  createdAt: number;
}

const MAX_ENTRIES = 10_000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
const ACCESS_TOKEN_TTL_MS = ID_TOKEN_TTL_SECONDS * 1000;
const TXN_COOKIE = "as_oidc_txn";
const ACR_RE = /^[\x21-\x7e]{1,128}$/;
// Usernames, email addresses (including plus aliases) and UUIDs.
const LOGIN_HINT_RE = /^[a-zA-Z0-9_.@+-]{1,128}$/;

const sessions = new Map<string, ProviderSession>();
const authorizationCodes = new Map<string, AuthorizationCode>();
const accessTokens = new Map<string, AccessToken>();

function sweep<T extends { createdAt: number }>(store: Map<string, T>, ttl: number): void {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (now - entry.createdAt > ttl) store.delete(key);
  }
}

setInterval(() => {
  sweep(sessions, SESSION_TTL_MS);
  sweep(authorizationCodes, CODE_TTL_MS);
  sweep(accessTokens, ACCESS_TOKEN_TTL_MS);
}, 60 * 1000).unref();

// ─── Helpers ───────────────────────────────────────────────────────────────

const provider = config.oidcProvider;
const issuer = config.app.baseUrl;
const callbackUrl = `${issuer}/oidc-provider/callback`;

function isRegisteredRedirectUri(value: string): boolean {
  try {
    return provider.redirectUris.includes(new URL(value).toString());
  } catch {
    return false;
  }
}

function redirectWithError(
  res: Response,
  redirectUri: string,
  state: string | undefined,
  error: string,
  description?: string
): void {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (description) url.searchParams.set("error_description", description);
  if (state) url.searchParams.set("state", state);
  res.redirect(url.toString());
}

function readClientCredentials(
  req: Request
): { clientId: string; clientSecret: string } | undefined {
  const header = req.headers.authorization;
  if (header?.startsWith("Basic ")) {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator > 0) {
      try {
        return {
          clientId: decodeURIComponent(decoded.slice(0, separator)),
          clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
        };
      } catch {
        return undefined;
      }
    }
    return undefined;
  }

  const clientId: unknown = req.body?.client_id;
  const clientSecret: unknown = req.body?.client_secret;
  if (typeof clientId === "string" && typeof clientSecret === "string") {
    return { clientId, clientSecret };
  }
  return undefined;
}

/** Maps Authsignal verification methods to RFC 8176 `amr` values. */
function toAmr(verificationMethods: string[]): string[] {
  const amr = new Set<string>();
  for (const method of verificationMethods) {
    switch (method) {
      case "PASSKEY":
      case "SECURITY_KEY":
        amr.add("hwk");
        amr.add("user");
        break;
      case "AUTHENTICATOR_APP":
      case "EMAIL_OTP":
        amr.add("otp");
        break;
      case "SMS":
      case "WHATSAPP":
        amr.add("sms");
        break;
      case "PUSH":
        amr.add("swk");
        break;
      default:
        break;
    }
  }
  amr.add("mfa");
  return [...amr];
}

function requireEnabled(_req: Request, res: Response, next: () => void): void {
  if (!provider.enabled) {
    res.status(503).json({ error: "temporarily_unavailable", error_description: "OIDC provider is not configured" });
    return;
  }
  next();
}

router.use(requireEnabled);

// ─── Discovery ─────────────────────────────────────────────────────────────

export function discoveryHandler(_req: Request, res: Response): void {
  if (!provider.enabled) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oidc-provider/authorize`,
    token_endpoint: `${issuer}/oidc-provider/token`,
    userinfo_endpoint: `${issuer}/oidc-provider/userinfo`,
    jwks_uri: `${issuer}/oidc-provider/jwks`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    claims_supported: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "acr",
      "amr",
      "authsignal_verification_methods",
    ],
  });
}

// ─── GET /oidc-provider/authorize ──────────────────────────────────────────

router.get("/authorize", async (req: Request, res: Response) => {
  const clientId = getQueryString(req.query.client_id);
  const redirectUri = getQueryString(req.query.redirect_uri);
  const state = getQueryString(req.query.state);

  // Never redirect to an unregistered client or redirect URI.
  if (!clientId || clientId !== provider.clientId) {
    res.status(400).json({ error: "invalid_client" });
    return;
  }
  if (!redirectUri || !isRegisteredRedirectUri(redirectUri)) {
    res.status(400).json({ error: "invalid_request", error_description: "redirect_uri is not registered" });
    return;
  }

  try {
    const responseType = getQueryString(req.query.response_type);
    const scope = getQueryString(req.query.scope);
    const nonce = getQueryString(req.query.nonce);
    const loginHint = getQueryString(req.query.login_hint);
    const codeChallenge = getQueryString(req.query.code_challenge);
    const codeChallengeMethod = getQueryString(req.query.code_challenge_method);
    const requestedAcr = getQueryString(req.query.acr_values)?.split(/\s+/)[0];

    if (responseType !== "code") {
      redirectWithError(res, redirectUri, state, "unsupported_response_type");
      return;
    }
    if (!scope?.split(/\s+/).includes("openid")) {
      redirectWithError(res, redirectUri, state, "invalid_scope");
      return;
    }
    if (!state || state.length > 2048) {
      redirectWithError(res, redirectUri, undefined, "invalid_request", "state is required");
      return;
    }
    if (nonce && nonce.length > 2048) {
      redirectWithError(res, redirectUri, state, "invalid_request", "nonce is too long");
      return;
    }
    if (codeChallenge && codeChallengeMethod !== "S256") {
      redirectWithError(res, redirectUri, state, "invalid_request", "code_challenge_method must be S256");
      return;
    }
    if (requestedAcr && !ACR_RE.test(requestedAcr)) {
      redirectWithError(res, redirectUri, state, "invalid_request", "invalid acr_values");
      return;
    }

    // This provider only performs a second factor for a user PingOne has
    // already identified, so the user has to arrive in login_hint.
    if (!loginHint) {
      redirectWithError(res, redirectUri, state, "login_required", "login_hint is required");
      return;
    }
    if (!LOGIN_HINT_RE.test(loginHint)) {
      redirectWithError(res, redirectUri, state, "invalid_request", "invalid login_hint");
      return;
    }

    if (sessions.size >= MAX_ENTRIES) {
      redirectWithError(res, redirectUri, state, "temporarily_unavailable");
      return;
    }

    const transactionId = generateState();
    const flowRedirectUrl = new URL(callbackUrl);
    flowRedirectUrl.searchParams.set("state", transactionId);

    const flow = await startFlow({
      actionCode: provider.flowActionCode,
      userId: loginHint,
      redirectUrl: flowRedirectUrl.toString(),
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    sessions.set(transactionId, {
      userId: loginHint,
      clientId,
      redirectUri,
      state,
      nonce,
      codeChallenge,
      requestedAcr,
      createdAt: Date.now(),
    });

    // Bind the transaction to this browser so a callback URL cannot be replayed elsewhere.
    res.cookie(TXN_COOKIE, transactionId, {
      signed: true,
      httpOnly: true,
      sameSite: "lax",
      secure: config.app.sessionCookieSecure,
      path: "/oidc-provider",
      maxAge: SESSION_TTL_MS,
    });

    res.redirect(flow.challengeUrl);
  } catch (error) {
    console.error("OIDC provider authorize error:", (error as Error).message);
    redirectWithError(res, redirectUri, state, "server_error");
  }
});

// ─── GET /oidc-provider/callback (from the Authsignal hosted UI) ────────────

router.get("/callback", async (req: Request, res: Response) => {
  const transactionId = getQueryString(req.query.state);
  const challengeToken = getQueryString(req.query.challenge_token);

  if (!transactionId) {
    res.status(400).json({ error: "invalid_request", error_description: "missing state" });
    return;
  }

  const session = sessions.get(transactionId);
  if (!session || Date.now() - session.createdAt > SESSION_TTL_MS) {
    sessions.delete(transactionId);
    res.status(400).json({ error: "invalid_request", error_description: "unknown or expired transaction" });
    return;
  }

  // The transaction must come back in the browser that started it. If it does
  // not, send the relying party an error (never a code) and leave the
  // transaction untouched for the browser that owns it.
  const boundTransaction: unknown = req.signedCookies?.[TXN_COOKIE];
  if (typeof boundTransaction !== "string" || !timingSafeEqualStrings(boundTransaction, transactionId)) {
    const reason =
      typeof boundTransaction !== "string"
        ? "the sign-in took too long or cookies are blocked"
        : "a newer sign-in was started in this browser";
    console.warn(`OIDC provider callback rejected: ${reason}`);
    redirectWithError(res, session.redirectUri, session.state, "access_denied", `${reason}; start the sign-in again`);
    return;
  }

  sessions.delete(transactionId);
  res.clearCookie(TXN_COOKIE, { path: "/oidc-provider" });

  if (!challengeToken) {
    redirectWithError(res, session.redirectUri, session.state, "access_denied", "verification was not completed");
    return;
  }

  try {
    const result = await verifyFlow({
      actionCode: provider.flowActionCode,
      challengeToken,
    });

    if (result.action.state !== "CHALLENGE_SUCCEEDED") {
      redirectWithError(res, session.redirectUri, session.state, "access_denied", "verification failed");
      return;
    }
    if (result.user?.userId && result.user.userId !== session.userId) {
      redirectWithError(res, session.redirectUri, session.state, "access_denied", "user mismatch");
      return;
    }

    const verificationMethods = [
      ...new Set(
        (result.action.completedSteps ?? [])
          .map((step) => step.verificationMethod)
          .filter((method): method is string => typeof method === "string")
      ),
    ];
    if (verificationMethods.length === 0) {
      // The flow finished without the user proving anything; do not report it as MFA.
      redirectWithError(res, session.redirectUri, session.state, "access_denied", "no verification step was completed");
      return;
    }

    if (authorizationCodes.size >= MAX_ENTRIES) {
      redirectWithError(res, session.redirectUri, session.state, "temporarily_unavailable");
      return;
    }

    const code = randomBytes(32).toString("base64url");
    authorizationCodes.set(code, {
      userId: session.userId,
      clientId: session.clientId,
      redirectUri: session.redirectUri,
      nonce: session.nonce,
      codeChallenge: session.codeChallenge,
      acr: session.requestedAcr,
      verificationMethods,
      authTime: Math.floor(Date.now() / 1000),
      createdAt: Date.now(),
    });

    const url = new URL(session.redirectUri);
    url.searchParams.set("code", code);
    url.searchParams.set("state", session.state);
    res.redirect(url.toString());
  } catch (error) {
    console.error("OIDC provider callback error:", (error as Error).message);
    // Authsignal rejects expired, reused or unfinished challenge tokens with a 4xx.
    const denied = error instanceof AuthsignalApiError && error.status >= 400 && error.status < 500;
    redirectWithError(
      res,
      session.redirectUri,
      session.state,
      denied ? "access_denied" : "server_error",
      denied ? "verification could not be confirmed" : undefined
    );
  }
});

// ─── POST /oidc-provider/token ─────────────────────────────────────────────

router.post("/token", async (req: Request, res: Response) => {
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");

  try {
    const credentials = readClientCredentials(req);
    const clientOk =
      credentials !== undefined &&
      timingSafeEqualStrings(credentials.clientId, provider.clientId ?? "") &&
      timingSafeEqualStrings(credentials.clientSecret, provider.clientSecret ?? "");
    if (!clientOk) {
      res.set("WWW-Authenticate", "Basic");
      res.status(401).json({ error: "invalid_client" });
      return;
    }

    if (req.body?.grant_type !== "authorization_code") {
      res.status(400).json({ error: "unsupported_grant_type" });
      return;
    }

    const code: unknown = req.body?.code;
    const entry = typeof code === "string" ? authorizationCodes.get(code) : undefined;
    if (typeof code !== "string" || !entry) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
    authorizationCodes.delete(code); // single use

    if (Date.now() - entry.createdAt > CODE_TTL_MS) {
      res.status(400).json({ error: "invalid_grant", error_description: "code expired" });
      return;
    }
    if (credentials.clientId !== entry.clientId) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    const redirectUri: unknown = req.body?.redirect_uri;
    if (typeof redirectUri !== "string" || redirectUri !== entry.redirectUri) {
      res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
      return;
    }

    if (entry.codeChallenge) {
      const verifier: unknown = req.body?.code_verifier;
      if (
        typeof verifier !== "string" ||
        !timingSafeEqualStrings(generateCodeChallenge(verifier), entry.codeChallenge)
      ) {
        res.status(400).json({ error: "invalid_grant", error_description: "code_verifier mismatch" });
        return;
      }
    }

    const idToken = await signIdToken({
      sub: entry.userId,
      aud: entry.clientId,
      nonce: entry.nonce,
      authTime: entry.authTime,
      acr: entry.acr,
      amr: toAmr(entry.verificationMethods),
      verificationMethods: entry.verificationMethods,
    });

    const accessToken = randomBytes(32).toString("base64url");
    if (accessTokens.size < MAX_ENTRIES) {
      accessTokens.set(accessToken, { userId: entry.userId, createdAt: Date.now() });
    }

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ID_TOKEN_TTL_SECONDS,
      id_token: idToken,
    });
  } catch (error) {
    console.error("OIDC provider token error:", (error as Error).message);
    res.status(500).json({ error: "server_error" });
  }
});

// ─── GET|POST /oidc-provider/userinfo ──────────────────────────────────────

function userinfoHandler(req: Request, res: Response): void {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
  const entry = token ? accessTokens.get(token) : undefined;

  if (!entry || Date.now() - entry.createdAt > ACCESS_TOKEN_TTL_MS) {
    res.set("WWW-Authenticate", 'Bearer error="invalid_token"');
    res.status(401).json({ error: "invalid_token" });
    return;
  }

  res.json({ sub: entry.userId });
}

router.get("/userinfo", userinfoHandler);
router.post("/userinfo", userinfoHandler);

// ─── GET /oidc-provider/jwks ───────────────────────────────────────────────

router.get("/jwks", (_req: Request, res: Response) => {
  res.set("Cache-Control", "public, max-age=3600");
  res.json(getJwks());
});

export default router;
