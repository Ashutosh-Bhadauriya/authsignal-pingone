/**
 * Demo Application Routes
 *
 * A reference implementation showing the PingOne + Authsignal integration
 * from a customer's perspective. MFA is handled by the federation bridge
 * (/oidc/initiate → Authsignal OIDC MFA → /oidc/callback → redirect back).
 *
 * Flow:
 * 1. Login via PingOne (OIDC auth code flow with PKCE)
 * 2. Auto-enroll verified email as EMAIL_OTP if user is new to Authsignal
 * 3. Redirect to the MFA federation bridge for Authsignal MFA
 * 4. Bridge handles MFA, redirects back to /demo/mfa-complete
 * 5. Session created only after MFA succeeds
 */

import { Router, type Request, type Response } from "express";
import { config } from "../config.js";
import * as pingoneService from "../services/pingone.js";
import * as authsignalService from "../services/authsignal.js";
import { consumeMfaResult } from "../services/mfa-results.js";
import { requireSession, sessionStore, MAX_SESSIONS } from "../middleware/auth.js";
import {
  generateState,
  generateNonce,
  generateCodeVerifier,
  generateCodeChallenge,
  generateSessionId,
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

// Cleanup expired entries
setInterval(() => {
  const now = Date.now();
  for (const [key, flow] of loginFlows) {
    if (now - flow.createdAt > 10 * 60 * 1000) {
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
 * GET /demo/login
 * Redirects the user to PingOne for authentication.
 */
router.get("/login", (_req: Request, res: Response) => {
  if (loginFlows.size >= MAX_LOGIN_FLOWS) {
    res.status(503).json({ error: "Service temporarily at capacity" });
    return;
  }

  const state = generateState();
  const nonce = generateNonce();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  loginFlows.set(state, { codeVerifier, nonce, createdAt: Date.now() });

  const authorizeUrl = pingoneService.buildAuthorizeUrl({
    redirectUri: `${config.app.baseUrl}/demo/callback`,
    state,
    nonce,
    codeChallenge,
  });

  res.redirect(authorizeUrl);
});

/**
 * GET /demo/callback
 * PingOne redirects here after authentication.
 * Exchanges the code, auto-enrolls if needed, then redirects to the
 * MFA federation bridge for Authsignal MFA.
 */
router.get("/callback", async (req: Request, res: Response) => {
  try {
    const code = getQueryString(req.query.code);
    const state = getQueryString(req.query.state);
    const error = getQueryString(req.query.error);

    if (error) {
      res.redirect(`/?error=${encodeURIComponent(error)}`);
      return;
    }

    if (!state || !code) {
      res.status(400).json({ error: "Missing state or code" });
      return;
    }

    const flow = loginFlows.get(state);
    if (!flow) {
      res.status(400).json({ error: "Invalid or expired state" });
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
router.get("/session", (req: Request, res: Response) => {
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

  res.json({
    authenticated: true,
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
    const session = (req as any).appSession as AppSession;

    const result = await authsignalService.trackAction({
      userId: session.userId,
      action: "manageSettings",
      attributes: {
        redirectUrl: `${config.app.baseUrl}/dashboard.html`,
        email: session.email,
        redirectToSettings: true,
      },
    });

    res.json({
      settingsUrl: result.url,
    });
  } catch (error) {
    console.error("MFA settings error:", (error as Error).message);
    res.status(500).json({ error: "Failed to load MFA settings" });
  }
});

/**
 * POST /demo/logout
 * Clears the local session and returns the PingOne signoff URL
 * so the frontend can also end the PingOne SSO session.
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

  // Build PingOne signoff URL to end the SSO session
  const { environmentId, authBaseUrl } = config.pingone;
  const pingOneSignoffUrl = `${authBaseUrl}/${environmentId}/as/signoff?post_logout_redirect_uri=${encodeURIComponent(config.app.baseUrl)}`;

  res.json({ success: true, signoffUrl: pingOneSignoffUrl });
});

export default router;
