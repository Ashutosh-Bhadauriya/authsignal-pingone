/**
 * OIDC Provider Routes
 *
 * Exposes the bridge as an OIDC provider so that PingOne DaVinci can use
 * its native OIDC connector node for seamless browser redirects instead
 * of the HTTP connector + Custom HTML workaround.
 *
 * Double-redirect flow:
 * 1. DaVinci OIDC node → GET /oidc-provider/authorize (with login_hint=userId)
 * 2. Bridge calls Authsignal /init-auth, redirects browser to Authsignal OIDC /auth
 * 3. User completes MFA in Authsignal's pre-built UI
 * 4. Authsignal → GET /oidc-provider/callback (bridge receives auth code)
 * 5. Bridge verifies MFA result, generates its own authorization code
 * 6. Bridge redirects browser to DaVinci's redirect_uri with code + state
 * 7. DaVinci OIDC node → POST /oidc-provider/token (exchanges code for ID token)
 * 8. Bridge returns signed ID token with MFA result claims
 */

import { randomBytes } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { config } from "../config.js";
import * as authsignalService from "../services/authsignal.js";
import { getJwks, signIdToken } from "../services/signing-keys.js";
import {
  generateState,
  generateNonce,
  generateCodeVerifier,
  generateCodeChallenge,
  timingSafeEqual,
} from "../utils/crypto.js";
import { verifyAuthsignalIdToken } from "../utils/jwt.js";
import {
  SAFE_IDENTIFIER_RE,
  SAFE_ACTION_RE,
  getQueryString,
  getStringClaim,
} from "../utils/validation.js";
import type {
  OidcProviderSession,
  OidcProviderAuthorizationCode,
} from "../types/index.js";

const router = Router();

// ─── In-memory stores ──────────────────────────────────────────────────────

const MAX_PROVIDER_SESSIONS = 10_000;
const MAX_AUTH_CODES = 10_000;
const SESSION_TTL_MS = 10 * 60 * 1000; // 10 minutes
const CODE_TTL_MS = 60 * 1000; // 60 seconds

const providerSessions = new Map<string, OidcProviderSession>();
const authorizationCodes = new Map<string, OidcProviderAuthorizationCode>();

// Clean up expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, session] of providerSessions) {
    if (now - session.createdAt > SESSION_TTL_MS) {
      providerSessions.delete(key);
    }
  }
  for (const [key, entry] of authorizationCodes) {
    if (now - entry.createdAt > CODE_TTL_MS) {
      authorizationCodes.delete(key);
    }
  }
}, 5 * 60 * 1000);

// ─── Redirect URI allowlist ────────────────────────────────────────────────

function buildAllowedOrigins(): string[] {
  const appOrigin = new URL(config.app.baseUrl).origin;
  const pingOneDomain = new URL(config.pingone.authBaseUrl).hostname.replace(
    "auth.",
    ""
  );

  return [
    appOrigin,
    `https://auth.${pingOneDomain}`,
    `https://apps.${pingOneDomain}`,
    `https://orchestrate-api.${pingOneDomain}`,
  ];
}

const allowedOrigins = buildAllowedOrigins();

function isAllowedRedirectUri(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (allowedOrigins.some((origin) => parsed.origin === origin)) return true;
    if (parsed.hostname.endsWith(".ngrok-free.dev")) return true;
    return false;
  } catch {
    return false;
  }
}

// ─── Client authentication helpers ─────────────────────────────────────────

function authenticateClient(req: Request): {
  clientId: string;
  clientSecret: string;
} | null {
  // Try client_secret_basic (Authorization header)
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
    const colonIndex = decoded.indexOf(":");
    if (colonIndex > 0) {
      return {
        clientId: decodeURIComponent(decoded.slice(0, colonIndex)),
        clientSecret: decodeURIComponent(decoded.slice(colonIndex + 1)),
      };
    }
  }

  // Fall back to client_secret_post (credentials in body)
  const clientId = req.body?.client_id;
  const clientSecret = req.body?.client_secret;
  if (typeof clientId === "string" && typeof clientSecret === "string") {
    return { clientId, clientSecret };
  }

  return null;
}

// ─── Discovery endpoint ────────────────────────────────────────────────────

export function discoveryHandler(_req: Request, res: Response): void {
  res.json({
    issuer: config.app.baseUrl,
    authorization_endpoint: `${config.app.baseUrl}/oidc-provider/authorize`,
    token_endpoint: `${config.app.baseUrl}/oidc-provider/token`,
    jwks_uri: `${config.app.baseUrl}/oidc-provider/jwks`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
    ],
    claims_supported: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "nonce",
      "action_state",
      "action_verification_method",
      "action",
    ],
    code_challenge_methods_supported: ["S256"],
  });
}

// ─── GET /oidc-provider/authorize ──────────────────────────────────────────

router.get("/authorize", async (req: Request, res: Response) => {
  try {
    const clientId = getQueryString(req.query.client_id);
    const redirectUri = getQueryString(req.query.redirect_uri);
    const responseType = getQueryString(req.query.response_type);
    const scope = getQueryString(req.query.scope);
    const davinciState = getQueryString(req.query.state);
    const davinciNonce = getQueryString(req.query.nonce);
    const loginHint = getQueryString(req.query.login_hint);
    const codeChallenge = getQueryString(req.query.code_challenge);
    const codeChallengeMethod = getQueryString(req.query.code_challenge_method);
    const emailParam = getQueryString(req.query.email);
    const actionParam = getQueryString(req.query.acr_values) ?? getQueryString(req.query.action);

    // Validate client_id before anything else (never redirect to unknown client)
    if (!config.oidcProvider.clientId) {
      res.status(500).json({ error: "OIDC provider not configured" });
      return;
    }
    if (!clientId || clientId !== config.oidcProvider.clientId) {
      res.status(400).json({ error: "invalid_client" });
      return;
    }

    // Validate redirect_uri before using it for error redirects
    if (!redirectUri) {
      res.status(400).json({ error: "missing redirect_uri" });
      return;
    }
    if (!isAllowedRedirectUri(redirectUri)) {
      res.status(400).json({ error: "invalid redirect_uri" });
      return;
    }

    // From here, errors can be returned as OIDC error redirects
    if (responseType !== "code") {
      const errorUrl = new URL(redirectUri);
      errorUrl.searchParams.set("error", "unsupported_response_type");
      if (davinciState) errorUrl.searchParams.set("state", davinciState);
      res.redirect(errorUrl.toString());
      return;
    }
    if (!scope?.includes("openid")) {
      const errorUrl = new URL(redirectUri);
      errorUrl.searchParams.set("error", "invalid_scope");
      if (davinciState) errorUrl.searchParams.set("state", davinciState);
      res.redirect(errorUrl.toString());
      return;
    }
    if (!davinciState) {
      const errorUrl = new URL(redirectUri);
      errorUrl.searchParams.set("error", "invalid_request");
      errorUrl.searchParams.set("error_description", "missing state");
      res.redirect(errorUrl.toString());
      return;
    }

    // Extract userId from login_hint
    const userId = loginHint;
    if (!userId) {
      const errorUrl = new URL(redirectUri);
      errorUrl.searchParams.set("error", "invalid_request");
      errorUrl.searchParams.set("error_description", "login_hint (userId) is required");
      errorUrl.searchParams.set("state", davinciState);
      res.redirect(errorUrl.toString());
      return;
    }
    if (!SAFE_IDENTIFIER_RE.test(userId)) {
      const errorUrl = new URL(redirectUri);
      errorUrl.searchParams.set("error", "invalid_request");
      errorUrl.searchParams.set("error_description", "invalid login_hint format");
      errorUrl.searchParams.set("state", davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    // Validate optional action
    const action = actionParam ?? "mfa";
    if (!SAFE_ACTION_RE.test(action)) {
      const errorUrl = new URL(redirectUri);
      errorUrl.searchParams.set("error", "invalid_request");
      errorUrl.searchParams.set("error_description", "invalid action format");
      errorUrl.searchParams.set("state", davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    // Validate PKCE if provided
    if (codeChallengeMethod && codeChallengeMethod !== "S256") {
      const errorUrl = new URL(redirectUri);
      errorUrl.searchParams.set("error", "invalid_request");
      errorUrl.searchParams.set("error_description", "only S256 code_challenge_method is supported");
      errorUrl.searchParams.set("state", davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    // Capacity check
    if (providerSessions.size >= MAX_PROVIDER_SESSIONS) {
      const errorUrl = new URL(redirectUri);
      errorUrl.searchParams.set("error", "server_error");
      errorUrl.searchParams.set("error_description", "service at capacity");
      errorUrl.searchParams.set("state", davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    // Generate internal PKCE + state + nonce for the Authsignal OIDC flow
    const internalState = generateState();
    const internalNonce = generateNonce();
    const authsignalCodeVerifier = generateCodeVerifier();
    const authsignalCodeChallenge = generateCodeChallenge(authsignalCodeVerifier);
    const authsignalRedirectUri = `${config.app.baseUrl}/oidc-provider/callback`;

    // Call Authsignal init-auth to get a scoped token
    const initResult = await authsignalService.oidcInitAuth({
      userId,
      action,
      email: emailParam,
    });

    // Store the provider session
    providerSessions.set(internalState, {
      internalState,
      internalNonce,
      authsignalCodeVerifier,
      authsignalRedirectUri,
      davinciRedirectUri: redirectUri,
      davinciState,
      davinciNonce,
      davinciClientId: clientId,
      davinciCodeChallenge: codeChallenge,
      davinciCodeChallengeMethod: codeChallengeMethod,
      userId,
      action,
      email: emailParam,
      createdAt: Date.now(),
    });

    // Build the Authsignal OIDC authorization URL
    const authUrl = new URL(`${config.authsignal.oidcUrl}/oidc/auth`);
    authUrl.searchParams.set("client_id", config.authsignal.tenantId);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("redirect_uri", authsignalRedirectUri);
    authUrl.searchParams.set("scope", "openid");
    authUrl.searchParams.set("state", internalState);
    authUrl.searchParams.set("nonce", internalNonce);
    authUrl.searchParams.set("code_challenge", authsignalCodeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("token", initResult.token);

    res.redirect(authUrl.toString());
  } catch (error) {
    console.error("OIDC provider authorize error:", (error as Error).message);
    res.status(500).json({ error: "server_error" });
  }
});

// ─── GET /oidc-provider/callback (internal — from Authsignal) ──────────────

router.get("/callback", async (req: Request, res: Response) => {
  try {
    const code = getQueryString(req.query.code);
    const state = getQueryString(req.query.state);
    const error = getQueryString(req.query.error);

    if (!state) {
      res.status(400).json({ error: "missing state" });
      return;
    }

    // Look up and consume the provider session
    const session = providerSessions.get(state);
    if (!session) {
      res.status(400).json({ error: "invalid or expired session" });
      return;
    }
    providerSessions.delete(state);

    // If Authsignal returned an error, redirect to DaVinci with error
    if (error || !code) {
      const errorUrl = new URL(session.davinciRedirectUri);
      errorUrl.searchParams.set("error", "access_denied");
      errorUrl.searchParams.set(
        "error_description",
        error ?? "mfa_challenge_failed"
      );
      errorUrl.searchParams.set("state", session.davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    // Exchange the code with Authsignal for tokens
    const tokens = await authsignalService.oidcTokenExchange({
      code,
      redirectUri: session.authsignalRedirectUri,
      codeVerifier: session.authsignalCodeVerifier,
    });

    // Verify the Authsignal ID token
    const claims = await verifyAuthsignalIdToken(
      tokens.id_token,
      config.authsignal.oidcUrl,
      config.authsignal.tenantId,
      session.internalNonce
    );

    const claimMap = claims as Record<string, unknown>;
    const actionState = getStringClaim(claimMap, "action_state");
    const actionCode = getStringClaim(claimMap, "action_code");
    const verificationMethod = getStringClaim(
      claimMap,
      "action_verification_method"
    );

    if (!actionState) {
      const errorUrl = new URL(session.davinciRedirectUri);
      errorUrl.searchParams.set("error", "server_error");
      errorUrl.searchParams.set(
        "error_description",
        "missing action_state in MFA response"
      );
      errorUrl.searchParams.set("state", session.davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    // Verify the token subject and action match expectations
    if (claims.sub && claims.sub !== session.userId) {
      const errorUrl = new URL(session.davinciRedirectUri);
      errorUrl.searchParams.set("error", "access_denied");
      errorUrl.searchParams.set("error_description", "user_mismatch");
      errorUrl.searchParams.set("state", session.davinciState);
      res.redirect(errorUrl.toString());
      return;
    }
    if (actionCode && actionCode !== session.action) {
      const errorUrl = new URL(session.davinciRedirectUri);
      errorUrl.searchParams.set("error", "access_denied");
      errorUrl.searchParams.set("error_description", "action_mismatch");
      errorUrl.searchParams.set("state", session.davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    const mfaSucceeded =
      actionState === "CHALLENGE_SUCCEEDED" || actionState === "ALLOW";

    if (!mfaSucceeded) {
      const errorUrl = new URL(session.davinciRedirectUri);
      errorUrl.searchParams.set("error", "access_denied");
      errorUrl.searchParams.set("error_description", `mfa_${actionState.toLowerCase()}`);
      errorUrl.searchParams.set("state", session.davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    // Capacity check for authorization codes
    if (authorizationCodes.size >= MAX_AUTH_CODES) {
      const errorUrl = new URL(session.davinciRedirectUri);
      errorUrl.searchParams.set("error", "server_error");
      errorUrl.searchParams.set("error_description", "service at capacity");
      errorUrl.searchParams.set("state", session.davinciState);
      res.redirect(errorUrl.toString());
      return;
    }

    // Generate an authorization code and store the MFA result
    const authCode = randomBytes(32).toString("base64url");

    authorizationCodes.set(authCode, {
      code: authCode,
      userId: session.userId,
      action: session.action,
      actionState,
      verificationMethod,
      davinciRedirectUri: session.davinciRedirectUri,
      davinciClientId: session.davinciClientId,
      davinciNonce: session.davinciNonce,
      davinciCodeChallenge: session.davinciCodeChallenge,
      davinciCodeChallengeMethod: session.davinciCodeChallengeMethod,
      createdAt: Date.now(),
    });

    // Redirect back to DaVinci with the authorization code
    const successUrl = new URL(session.davinciRedirectUri);
    successUrl.searchParams.set("code", authCode);
    successUrl.searchParams.set("state", session.davinciState);
    res.redirect(successUrl.toString());
  } catch (error) {
    console.error("OIDC provider callback error:", (error as Error).message);
    res.status(500).json({ error: "server_error" });
  }
});

// ─── POST /oidc-provider/token ─────────────────────────────────────────────

router.post("/token", async (req: Request, res: Response) => {
  try {
    // Authenticate the client
    const clientCreds = authenticateClient(req);
    if (!clientCreds) {
      res.status(401).json({ error: "invalid_client", error_description: "missing credentials" });
      return;
    }

    if (!config.oidcProvider.clientId || !config.oidcProvider.clientSecret) {
      res.status(500).json({ error: "server_error", error_description: "OIDC provider not configured" });
      return;
    }

    if (
      clientCreds.clientId !== config.oidcProvider.clientId ||
      !timingSafeEqual(clientCreds.clientSecret, config.oidcProvider.clientSecret)
    ) {
      res.status(401).json({ error: "invalid_client" });
      return;
    }

    // Validate grant type
    const grantType = req.body?.grant_type;
    if (grantType !== "authorization_code") {
      res.status(400).json({ error: "unsupported_grant_type" });
      return;
    }

    // Look up the authorization code
    const code = req.body?.code;
    if (typeof code !== "string") {
      res.status(400).json({ error: "invalid_grant", error_description: "missing code" });
      return;
    }

    const entry = authorizationCodes.get(code);
    if (!entry) {
      res.status(400).json({ error: "invalid_grant", error_description: "unknown or expired code" });
      return;
    }

    // Single-use: delete immediately
    authorizationCodes.delete(code);

    // Check TTL
    if (Date.now() - entry.createdAt > CODE_TTL_MS) {
      res.status(400).json({ error: "invalid_grant", error_description: "code expired" });
      return;
    }

    // Validate redirect_uri matches the one from the authorize request
    const redirectUri = req.body?.redirect_uri;
    if (typeof redirectUri === "string" && redirectUri !== entry.davinciRedirectUri) {
      res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
      return;
    }

    // Validate client_id matches
    if (clientCreds.clientId !== entry.davinciClientId) {
      res.status(400).json({ error: "invalid_grant", error_description: "client_id mismatch" });
      return;
    }

    // Validate PKCE if it was used in the authorize request
    if (entry.davinciCodeChallenge) {
      const codeVerifier = req.body?.code_verifier;
      if (typeof codeVerifier !== "string") {
        res.status(400).json({ error: "invalid_grant", error_description: "code_verifier required" });
        return;
      }
      const computedChallenge = generateCodeChallenge(codeVerifier);
      if (computedChallenge !== entry.davinciCodeChallenge) {
        res.status(400).json({ error: "invalid_grant", error_description: "code_verifier mismatch" });
        return;
      }
    }

    // Sign the ID token with MFA result claims
    const idToken = await signIdToken({
      sub: entry.userId,
      aud: entry.davinciClientId,
      nonce: entry.davinciNonce,
      action_state: entry.actionState,
      action_verification_method: entry.verificationMethod,
      action: entry.action,
    });

    const accessToken = randomBytes(32).toString("base64url");

    res.json({
      id_token: idToken,
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 300,
    });
  } catch (error) {
    console.error("OIDC provider token error:", (error as Error).message);
    res.status(500).json({ error: "server_error" });
  }
});

// ─── GET /oidc-provider/jwks ───────────────────────────────────────────────

router.get("/jwks", (_req: Request, res: Response) => {
  res.json(getJwks());
});

export default router;
