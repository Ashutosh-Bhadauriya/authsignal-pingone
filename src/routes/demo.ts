/**
 * Demo Application Routes
 *
 * A working demo showing the full PingOne + Authsignal integration:
 * 1. Login via PingOne (OIDC auth code flow with PKCE)
 * 2. MFA step-up via Authsignal (track -> challenge -> validate)
 * 3. Passwordless passkey login via Authsignal
 * 4. MFA settings management
 */

import { Router, type Request, type Response } from "express";
import { config } from "../config.js";
import * as pingoneService from "../services/pingone.js";
import * as authsignalService from "../services/authsignal.js";
import { requireSession, sessionStore } from "../middleware/auth.js";
import {
  generateState,
  generateNonce,
  generateCodeVerifier,
  generateCodeChallenge,
  generateSessionId,
} from "../utils/crypto.js";
import type { AppSession } from "../types/index.js";

const router = Router();

const MAX_LOGIN_FLOWS = 10_000;
const MAX_PENDING_MFA = 10_000;

// In-memory PKCE store for login flows (use Redis in production)
const loginFlows = new Map<
  string,
  { codeVerifier: string; nonce: string; createdAt: number }
>();

// Pending MFA sessions - stores user context until MFA completes.
// Sessions are NOT created until MFA succeeds (prevents MFA bypass).
const pendingMfa = new Map<
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
  for (const [key, pending] of pendingMfa) {
    if (now - pending.createdAt > 10 * 60 * 1000) {
      pendingMfa.delete(key);
    }
  }
}, 5 * 60 * 1000);

function setSessionCookie(res: Response, sessionId: string): void {
  res.cookie("session_id", sessionId, {
    httpOnly: true,
    secure: config.app.baseUrl.startsWith("https"),
    sameSite: "lax",
    maxAge: config.app.sessionMaxAge * 1000,
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
 * Exchanges the code, then initiates Authsignal MFA step-up.
 */
router.get("/callback", async (req: Request, res: Response) => {
  try {
    const { code, state, error } = req.query as Record<string, string>;

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
    const email = (idClaims as any).email as string | undefined;
    const name = (idClaims as any).name as string | undefined;

    // Auto-enroll the user's PingOne email as an EMAIL_OTP authenticator
    // if they don't have any authenticators yet
    const user = await authsignalService.getUser(userId);
    if (!user.isEnrolled && email) {
      await authsignalService.enrollVerifiedAuthenticator({
        userId,
        verificationMethod: authsignalService.AuthsignalVerificationMethod.EMAIL_OTP,
        email,
        isDefault: true,
      });
    }

    // Now initiate Authsignal MFA step-up
    const mfaResult = await authsignalService.trackAction({
      userId,
      action: "signIn",
      attributes: {
        redirectUrl: `${config.app.baseUrl}/demo/mfa-callback`,
        email,
      },
    });

    if (mfaResult.state === "CHALLENGE_REQUIRED" && mfaResult.url) {
      if (pendingMfa.size >= MAX_PENDING_MFA) {
        res.redirect(`/?error=${encodeURIComponent("Service at capacity")}`);
        return;
      }

      // Store pending MFA context - NO session created yet.
      // The session is only created after MFA succeeds.
      pendingMfa.set(mfaResult.idempotencyKey, {
        userId,
        email,
        displayName: name,
        createdAt: Date.now(),
      });

      // Redirect to Authsignal pre-built UI for enrollment or MFA challenge
      res.redirect(mfaResult.url);
    } else if (
      mfaResult.state === "ALLOW" ||
      mfaResult.state === "CHALLENGE_SUCCEEDED"
    ) {
      // MFA not required and user is already enrolled (rules allow)
      const sessionId = generateSessionId();
      const session: AppSession = {
        userId,
        pingOneUserId: userId,
        email,
        displayName: name,
        mfaVerified: mfaResult.state === "CHALLENGE_SUCCEEDED",
        authenticatedAt: Date.now(),
        expiresAt: Date.now() + config.app.sessionMaxAge * 1000,
      };
      sessionStore.set(sessionId, session);
      setSessionCookie(res, sessionId);
      res.redirect("/dashboard.html");
    } else {
      res.redirect(`/?error=${encodeURIComponent("Authentication blocked")}`);
    }
  } catch (error) {
    console.error("Demo callback error:", (error as Error).message);
    res.redirect(`/?error=${encodeURIComponent("Authentication failed")}`);
  }
});

/**
 * GET /demo/mfa-callback
 * Authsignal redirects here after MFA challenge completion.
 * Validates the token and creates a new session only if MFA succeeded.
 */
router.get("/mfa-callback", async (req: Request, res: Response) => {
  try {
    const token = req.query.token as string;
    if (!token) {
      res.redirect(`/?error=${encodeURIComponent("Missing MFA token")}`);
      return;
    }

    // Validate the MFA challenge
    const validation = await authsignalService.validateChallenge(token);

    if (!validation.isValid) {
      res.redirect(
        `/?error=${encodeURIComponent("MFA verification failed")}`
      );
      return;
    }

    // Look up the pending MFA context using the idempotency key
    const pending = pendingMfa.get(validation.idempotencyKey);
    if (!pending) {
      res.redirect(`/?error=${encodeURIComponent("MFA session expired")}`);
      return;
    }
    pendingMfa.delete(validation.idempotencyKey);

    // Verify the validated userId matches the pending user (prevents cross-user MFA swap)
    if (validation.userId && validation.userId !== pending.userId) {
      res.redirect(`/?error=${encodeURIComponent("User mismatch")}`);
      return;
    }

    // NOW create the session - MFA is verified
    const sessionId = generateSessionId();
    const session: AppSession = {
      userId: pending.userId,
      pingOneUserId: pending.userId,
      email: pending.email,
      displayName: pending.displayName,
      mfaVerified: true,
      mfaMethod: validation.verificationMethod,
      authenticatedAt: Date.now(),
      expiresAt: Date.now() + config.app.sessionMaxAge * 1000,
    };
    sessionStore.set(sessionId, session);
    setSessionCookie(res, sessionId);

    res.redirect("/dashboard.html");
  } catch (error) {
    console.error("MFA callback error:", (error as Error).message);
    res.redirect(`/?error=${encodeURIComponent("MFA validation failed")}`);
  }
});

/**
 * POST /demo/passkey-callback
 * Validates a passkey sign-in token from the Authsignal browser SDK.
 * Creates a session directly (no PingOne involved - pure passwordless).
 */
router.post("/passkey-callback", async (req: Request, res: Response) => {
  try {
    const { token } = req.body as { token?: string };
    if (!token) {
      res.status(400).json({ success: false, error: "Missing token" });
      return;
    }

    const validation = await authsignalService.validateChallenge(token);

    if (!validation.isValid || !validation.userId) {
      res.status(401).json({ success: false, error: "Passkey verification failed" });
      return;
    }

    // Get user info from Authsignal
    const user = await authsignalService.getUser(validation.userId);

    const sessionId = generateSessionId();
    const session: AppSession = {
      userId: validation.userId,
      pingOneUserId: validation.userId,
      email: user.email,
      displayName: user.displayName,
      mfaVerified: true,
      mfaMethod: validation.verificationMethod,
      authenticatedAt: Date.now(),
      expiresAt: Date.now() + config.app.sessionMaxAge * 1000,
    };
    sessionStore.set(sessionId, session);
    setSessionCookie(res, sessionId);

    res.json({ success: true });
  } catch (error) {
    console.error("Passkey callback error:", (error as Error).message);
    res.status(500).json({ success: false, error: "Passkey verification failed" });
  }
});

/**
 * GET /demo/session
 * Returns the current session info (for frontend to display).
 */
router.get("/session", (req: Request, res: Response) => {
  const sessionId = req.cookies?.["session_id"];
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
      token: result.token,
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
  const sessionId = req.cookies?.["session_id"];
  if (sessionId) {
    sessionStore.delete(sessionId);
  }
  res.clearCookie("session_id");

  // Build PingOne signoff URL to end the SSO session
  const { environmentId, authBaseUrl } = config.pingone;
  const pingOneSignoffUrl = `${authBaseUrl}/${environmentId}/as/signoff?post_logout_redirect_uri=${encodeURIComponent(config.app.baseUrl)}`;

  res.json({ success: true, signoffUrl: pingOneSignoffUrl });
});

export default router;
