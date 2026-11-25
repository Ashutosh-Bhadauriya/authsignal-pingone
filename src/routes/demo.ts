/**
 * Demo Application Routes
 *
 * A stand-in for a customer's application. It has two sign-in modes:
 *
 * DaVinci (used when DAVINCI_* is configured)
 * 1. The sign-in page asks /demo/davinci/start for an SDK token and renders
 *    the DaVinci widget in the page
 * 2. The flow redirects to Authsignal through the OIDC provider in
 *    ./oidc-provider.ts and DaVinci returns the browser to the sign-in page
 *    with a continue token
 * 3. The widget finishes the flow and the page posts the signed result to
 *    /demo/davinci/complete, which verifies it and creates the session
 *
 * Legacy PingOne (classic actions, see docs/legacy-demo.md). MFA is handled by
 * the federation bridge (/oidc/initiate → Authsignal OIDC MFA → /oidc/callback).
 *
 * Legacy flow:
 * 1. Login via PingOne (OIDC auth code flow with PKCE)
 * 2. Auto-enroll verified email as EMAIL_OTP if user is new to Authsignal
 * 3. Redirect to the MFA federation bridge for Authsignal MFA
 * 4. Bridge handles MFA, redirects back to /demo/mfa-complete
 * 5. Session created only after MFA succeeds
 */

import { Router, type Request, type Response } from "express";
import { config } from "../config.js";
import * as pingoneService from "../services/pingone.js";
import * as davinciService from "../services/davinci.js";
import * as authsignalService from "../services/authsignal.js";
import { consumeMfaResult } from "../services/mfa-results.js";
import { requireSession, sessionStore, MAX_SESSIONS } from "../middleware/auth.js";
import {
  generateState,
  generateNonce,
  generateCodeVerifier,
  generateCodeChallenge,
  generateSessionId,
  timingSafeEqualStrings,
} from "../utils/crypto.js";
import { getQueryString } from "../utils/validation.js";
import type { AppSession } from "../types/index.js";

const router = Router();

const MAX_LOGIN_FLOWS = 10_000;
const MAX_PENDING_LOGINS = 10_000;

// In-memory PKCE store for PingOne login flows (use Redis in production)
const loginFlows = new Map<
  string,
  { codeVerifier: string; nonce: string; createdAt: number }
>();

// Binds a login attempt to the browser that started it.
const LOGIN_COOKIE = "demo_login";
const LOGIN_TTL_MS = 30 * 60 * 1000;

const loginCookieOptions = {
  httpOnly: true,
  secure: config.app.sessionCookieSecure,
  sameSite: "lax" as const,
  signed: true,
  path: "/demo",
};

// Pending logins — stores user context until MFA completes via the bridge.
// Sessions are NOT created until MFA succeeds (prevents MFA bypass).
// Keyed by callbackState (a one-time CSRF token for the bridge round-trip).
const pendingLogins = new Map<
  string,
  {
    userId: string;
    email?: string;
    displayName?: string;
    createdAt: number;
  }
>();

// DaVinci interactions that already produced a session, so a signed response
// cannot be replayed while it is still valid.
const usedInteractions = new Map<string, number>();
const SAFE_USERNAME_RE = /^[a-zA-Z0-9_.@+-]{1,128}$/;

// Cleanup expired entries
setInterval(() => {
  const now = Date.now();
  for (const [key, usedAt] of usedInteractions) {
    if (now - usedAt > 24 * 60 * 60 * 1000) {
      usedInteractions.delete(key);
    }
  }
  for (const [key, flow] of loginFlows) {
    if (now - flow.createdAt > LOGIN_TTL_MS) {
      loginFlows.delete(key);
    }
  }
  for (const [key, pending] of pendingLogins) {
    if (now - pending.createdAt > 10 * 60 * 1000) {
      pendingLogins.delete(key);
    }
  }
}, 5 * 60 * 1000);

function setSessionCookie(res: Response, sessionId: string): void {
  res.cookie("session_id", sessionId, {
    httpOnly: true,
    secure: config.app.sessionCookieSecure,
    sameSite: "lax",
    maxAge: config.app.sessionMaxAge * 1000,
    signed: true,
  });
}

/**
 * GET /demo/config
 * Tells the front end which sign-in mode is active.
 */
router.get("/config", (_req: Request, res: Response) => {
  if (!config.davinci.enabled) {
    res.json({ provider: "pingone" });
    return;
  }
  res.json({
    provider: "davinci",
    companyId: config.davinci.environmentId,
    policyId: config.davinci.policyId,
    apiRoot: config.davinci.apiRoot,
    assetsOrigin: config.davinci.assetsOrigin,
  });
});

/**
 * GET /demo/login
 * Legacy mode: redirects the user to PingOne for authentication.
 */
router.get("/login", (_req: Request, res: Response) => {
  // In DaVinci mode sign-in happens in the page, through the widget.
  if (config.davinci.enabled) {
    res.redirect("/");
    return;
  }

  if (loginFlows.size >= MAX_LOGIN_FLOWS) {
    res.status(503).json({ error: "Service temporarily at capacity" });
    return;
  }

  const state = generateState();
  const nonce = generateNonce();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  loginFlows.set(state, { codeVerifier, nonce, createdAt: Date.now() });
  res.cookie(LOGIN_COOKIE, state, { ...loginCookieOptions, maxAge: LOGIN_TTL_MS });

  const authorizeParams = {
    redirectUri: `${config.app.baseUrl}/demo/callback`,
    state,
    nonce,
    codeChallenge,
  };

  res.redirect(pingoneService.buildAuthorizeUrl(authorizeParams));
});

/**
 * GET /demo/davinci/start
 * Hands the sign-in page what it needs to render the DaVinci widget.
 */
router.get("/davinci/start", async (_req: Request, res: Response) => {
  if (!config.davinci.enabled) {
    res.status(404).json({ error: "DaVinci is not configured" });
    return;
  }
  try {
    const token = await davinciService.getSdkToken();
    // The nonce goes into the flow as an input parameter and comes back inside
    // DaVinci's signed response. The cookie ties that response to this browser.
    const nonce = generateNonce();
    res.cookie(LOGIN_COOKIE, nonce, { ...loginCookieOptions, maxAge: LOGIN_TTL_MS });
    res.set("Cache-Control", "no-store");
    res.json({ token, nonce });
  } catch (error) {
    console.error("DaVinci start error:", (error as Error).message);
    res.status(502).json({ error: "Could not start sign-in" });
  }
});

/**
 * POST /demo/davinci/complete
 * Receives the flow's success response from the widget.
 */
router.post("/davinci/complete", async (req: Request, res: Response) => {
  if (!config.davinci.enabled) {
    res.status(404).json({ error: "DaVinci is not configured" });
    return;
  }

  const expectedNonce = req.signedCookies?.[LOGIN_COOKIE];
  res.clearCookie(LOGIN_COOKIE, loginCookieOptions);

  try {
    // The browser relays the result, so only the part DaVinci signed counts.
    const signedResponse = (req.body as { signedResponse?: unknown } | undefined)?.signedResponse;
    if (typeof signedResponse !== "string" || !signedResponse) {
      res.status(400).json({ error: "Sign-in result was not signed" });
      return;
    }

    const claims = (await davinciService.verifyDavinciJwt(signedResponse)) as Record<string, unknown>;
    const parameters = (claims.parameters ?? {}) as Record<string, unknown>;
    const properties = (claims.additionalProperties ?? {}) as Record<string, unknown>;
    const nonce = typeof parameters.nonce === "string" ? parameters.nonce : "";
    const username = typeof properties.username === "string" ? properties.username : "";
    const interactionId = typeof claims.interactionId === "string" ? claims.interactionId : "";

    // A signed flow response from this environment and, when pinned, this flow.
    if (
      claims.usage !== "flowResponse" ||
      claims.companyId !== config.davinci.environmentId ||
      (config.davinci.flowId && claims.flowId !== config.davinci.flowId)
    ) {
      res.status(403).json({ error: "Sign-in was not completed" });
      return;
    }
    if (typeof expectedNonce !== "string" || !nonce || !timingSafeEqualStrings(nonce, expectedNonce)) {
      res.status(403).json({ error: "Sign-in expired. Start again." });
      return;
    }
    if (!interactionId || usedInteractions.has(interactionId)) {
      res.status(403).json({ error: "Sign-in result was already used" });
      return;
    }
    // "username" is the value the flow sent to Authsignal as login_hint, so it
    // is also the Authsignal user ID.
    if (!SAFE_USERNAME_RE.test(username)) {
      res.status(403).json({ error: "Sign-in result has no username" });
      return;
    }

    if (sessionStore.size >= MAX_SESSIONS) {
      res.status(503).json({ error: "Service at capacity" });
      return;
    }
    usedInteractions.set(interactionId, Date.now());

    const sessionId = generateSessionId();
    sessionStore.set(sessionId, {
      userId: username,
      pingOneUserId: username,
      provider: "davinci",
      mfaVerified: false,
      authenticatedAt: Date.now(),
      expiresAt: Date.now() + config.app.sessionMaxAge * 1000,
    });
    setSessionCookie(res, sessionId);
    res.json({ success: true });
  } catch (error) {
    console.error("DaVinci complete error:", (error as Error).message);
    res.status(403).json({ error: "Sign-in result could not be verified" });
  }
});

/**
 * GET /demo/callback
 * Legacy mode: PingOne redirects here after authentication.
 * Exchanges the code, auto-enrolls if needed, then redirects to the MFA
 * federation bridge for Authsignal MFA.
 */
router.get("/callback", async (req: Request, res: Response) => {
  try {
    const code = getQueryString(req.query.code);
    const state = getQueryString(req.query.state);
    const error = getQueryString(req.query.error);
    const loginCookie = req.signedCookies?.[LOGIN_COOKIE];
    res.clearCookie(LOGIN_COOKIE, loginCookieOptions);

    if (error) {
      res.redirect(`/?error=${encodeURIComponent(error.slice(0, 200))}`);
      return;
    }

    if (!state || !code) {
      res.redirect(`/?error=${encodeURIComponent("Sign-in response was incomplete")}`);
      return;
    }

    const flow = loginFlows.get(state);
    if (!flow || loginCookie !== state) {
      res.redirect(`/?error=${encodeURIComponent("Sign-in expired. Start again.")}`);
      return;
    }
    loginFlows.delete(state);

    // Exchange the authorization code for PingOne tokens
    const tokens = await pingoneService.exchangeCode({
      code,
      redirectUri: `${config.app.baseUrl}/demo/callback`,
      codeVerifier: flow.codeVerifier,
    });

    // Verify the ID token with nonce validation
    const idClaims = await pingoneService.verifyIdToken(
      tokens.id_token,
      flow.nonce
    );
    const userId = idClaims.sub!;
    const claimMap = idClaims as Record<string, unknown>;
    const email = typeof claimMap.email === "string" ? claimMap.email : undefined;
    const emailVerified = claimMap.email_verified === true;
    const name = typeof claimMap.name === "string" ? claimMap.name : undefined;

    // Auto-enroll the user's PingOne email as an EMAIL_OTP authenticator
    // if they don't have any authenticators yet.
    // Only enroll if PingOne has verified the email (email_verified === true).
    const user = await authsignalService.getUser(userId);
    if (!user.isEnrolled && email && emailVerified) {
      await authsignalService.enrollVerifiedAuthenticator({
        userId,
        verificationMethod: authsignalService.AuthsignalVerificationMethod.EMAIL_OTP,
        email,
        isDefault: true,
      });
    }

    // Store pending login context — session is NOT created until MFA succeeds
    if (pendingLogins.size >= MAX_PENDING_LOGINS) {
      res.redirect(`/?error=${encodeURIComponent("Service at capacity")}`);
      return;
    }

    const callbackState = generateState();
    pendingLogins.set(callbackState, {
      userId,
      email,
      displayName: name,
      createdAt: Date.now(),
    });

    // Redirect to the MFA federation bridge
    const bridgeUrl = new URL(`${config.app.baseUrl}/oidc/initiate`);
    bridgeUrl.searchParams.set("user_id", userId);
    if (email) bridgeUrl.searchParams.set("email", email);
    bridgeUrl.searchParams.set("action", "signIn");
    bridgeUrl.searchParams.set("callback_url", `${config.app.baseUrl}/demo/mfa-complete`);
    bridgeUrl.searchParams.set("callback_state", callbackState);

    res.redirect(bridgeUrl.toString());
  } catch (error) {
    console.error("Demo callback error:", (error as Error).message);
    res.redirect(`/?error=${encodeURIComponent("Authentication failed")}`);
  }
});

/**
 * GET /demo/mfa-complete
 * The MFA federation bridge redirects here after Authsignal MFA completes.
 * Creates a session only if MFA succeeded.
 */
router.get("/mfa-complete", (req: Request, res: Response) => {
  try {
    const callbackState = getQueryString(req.query.callback_state);

    if (!callbackState) {
      res.redirect(`/?error=${encodeURIComponent("Missing callback state")}`);
      return;
    }

    const mfaResult = consumeMfaResult(callbackState);
    if (!mfaResult) {
      res.redirect(`/?error=${encodeURIComponent("MFA verification incomplete")}`);
      return;
    }

    // Look up and consume the pending login (one-time use)
    const pending = pendingLogins.get(callbackState);
    if (!pending) {
      res.redirect(`/?error=${encodeURIComponent("Login session expired")}`);
      return;
    }
    pendingLogins.delete(callbackState);

    // Verify the Authsignal-verified bridge result matches the pending login.
    if (mfaResult.userId !== pending.userId) {
      res.redirect(`/?error=${encodeURIComponent("User mismatch")}`);
      return;
    }

    if (!mfaResult.success) {
      const msg = mfaResult.error || "MFA verification failed";
      res.redirect(`/?error=${encodeURIComponent(msg)}`);
      return;
    }

    // MFA succeeded — create session
    if (sessionStore.size >= MAX_SESSIONS) {
      res.redirect(`/?error=${encodeURIComponent("Service at capacity")}`);
      return;
    }

    const sessionId = generateSessionId();
    const session: AppSession = {
      userId: pending.userId,
      pingOneUserId: pending.userId,
      provider: "pingone",
      email: pending.email,
      displayName: pending.displayName,
      mfaVerified: true,
      mfaMethod: mfaResult.verificationMethod,
      authenticatedAt: Date.now(),
      expiresAt: Date.now() + config.app.sessionMaxAge * 1000,
    };
    sessionStore.set(sessionId, session);
    setSessionCookie(res, sessionId);

    res.redirect("/dashboard.html");
  } catch (error) {
    console.error("MFA complete error:", (error as Error).message);
    res.redirect(`/?error=${encodeURIComponent("MFA completion failed")}`);
  }
});

/**
 * GET /demo/session
 * Returns the current session info (for frontend to display).
 */
router.get("/session", async (req: Request, res: Response) => {
  const sessionId = req.signedCookies?.["session_id"];
  if (!sessionId) {
    res.status(401).json({ authenticated: false });
    return;
  }

  const session = sessionStore.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessionStore.delete(sessionId);
    res.status(401).json({ authenticated: false });
    return;
  }

  // Authenticators the user has in Authsignal, read live so the list is
  // current after a visit to the settings page.
  let enrolledMethods: string[] | undefined;
  try {
    const user = await authsignalService.getUser(session.userId);
    enrolledMethods = user.enrolledVerificationMethods;
  } catch (error) {
    console.error("Authsignal getUser error:", (error as Error).message);
  }

  res.json({
    authenticated: true,
    provider: session.provider,
    enrolledMethods,
    userId: session.userId,
    email: session.email,
    displayName: session.displayName,
    mfaVerified: session.mfaVerified,
    mfaMethod: session.mfaMethod,
    authenticatedAt: session.authenticatedAt,
  });
});

/**
 * POST /demo/mfa-settings
 * Initiates the Authsignal settings flow for managing authenticators.
 */
router.post("/mfa-settings", requireSession, async (req: Request, res: Response) => {
  try {
    const session = req.appSession!;

    const settingsUrl = await authsignalService.getManageSettingsUrl({
      userId: session.userId,
      email: session.email,
      redirectUrl: `${config.app.baseUrl}/dashboard.html`,
    });

    res.json({ settingsUrl });
  } catch (error) {
    console.error("MFA settings error:", (error as Error).message);
    res.status(500).json({ error: "Failed to load MFA settings" });
  }
});

/**
 * POST /demo/logout
 * Clears the local session. In legacy mode it also returns the PingOne
 * signoff URL so the frontend can end the PingOne SSO session.
 */
router.post("/logout", (req: Request, res: Response) => {
  const sessionId = req.signedCookies?.["session_id"];
  if (sessionId) {
    sessionStore.delete(sessionId);
  }
  res.clearCookie("session_id", {
    httpOnly: true,
    secure: config.app.sessionCookieSecure,
    sameSite: "lax",
    signed: true,
  });

  // The DaVinci flow keeps no SSO session, so there is nothing else to end.
  if (config.davinci.enabled) {
    res.json({ success: true });
    return;
  }

  // Build PingOne signoff URL to end the SSO session
  const { environmentId, authBaseUrl } = config.pingone;
  const pingOneSignoffUrl = `${authBaseUrl}/${environmentId}/as/signoff?post_logout_redirect_uri=${encodeURIComponent(config.app.baseUrl)}`;

  res.json({ success: true, signoffUrl: pingOneSignoffUrl });
});

export default router;
