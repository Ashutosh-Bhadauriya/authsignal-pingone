/**
 * Demo Application Routes
 *
 * A working demo showing the full PingOne + Authsignal integration:
 * 1. Login via PingOne (OIDC auth code flow with PKCE)
 * 2. MFA step-up via Authsignal (track → challenge → validate)
 * 3. Passwordless passkey login via Authsignal
 * 4. MFA settings management
 */

import { Router, type Request, type Response } from "express";
import { config } from "../config.js";
import * as pingoneService from "../services/pingone.js";
import * as authsignalService from "../services/authsignal.js";
import { sessionStore } from "../middleware/auth.js";
import {
  generateState,
  generateNonce,
  generateCodeVerifier,
  generateCodeChallenge,
  generateSessionId,
} from "../utils/crypto.js";
import type { AppSession } from "../types/index.js";

const router = Router();

// In-memory PKCE store for login flows (use Redis in production)
const loginFlows = new Map<
  string,
  { codeVerifier: string; nonce: string; createdAt: number }
>();

// Cleanup expired login flows
setInterval(() => {
  const now = Date.now();
  for (const [key, flow] of loginFlows) {
    if (now - flow.createdAt > 10 * 60 * 1000) {
      loginFlows.delete(key);
    }
  }
}, 5 * 60 * 1000);

/**
 * GET /demo/login
 * Redirects the user to PingOne for authentication.
 */
router.get("/login", (_req: Request, res: Response) => {
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

    // Verify the ID token
    const idClaims = await pingoneService.verifyIdToken(tokens.id_token);
    const userId = idClaims.sub!;
    const email = (idClaims as any).email as string | undefined;
    const name = (idClaims as any).name as string | undefined;

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
      // Store partial session - MFA not yet verified
      const sessionId = generateSessionId();
      sessionStore.set(sessionId, {
        userId,
        pingOneUserId: userId,
        email,
        displayName: name,
        mfaVerified: false,
        authenticatedAt: Date.now(),
        expiresAt: Date.now() + config.app.sessionMaxAge * 1000,
        _mfaToken: mfaResult.token,
      });

      res.cookie("session_id", sessionId, {
        httpOnly: true,
        secure: config.app.baseUrl.startsWith("https"),
        sameSite: "lax",
        maxAge: config.app.sessionMaxAge * 1000,
      });

      // Redirect to Authsignal pre-built UI for MFA
      res.redirect(mfaResult.url);
    } else if (
      mfaResult.state === "ALLOW" ||
      mfaResult.state === "CHALLENGE_SUCCEEDED"
    ) {
      // MFA not required or already succeeded (e.g., rules allow)
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

      res.cookie("session_id", sessionId, {
        httpOnly: true,
        secure: config.app.baseUrl.startsWith("https"),
        sameSite: "lax",
        maxAge: config.app.sessionMaxAge * 1000,
      });

      res.redirect("/dashboard.html");
    } else {
      res.redirect(`/?error=${encodeURIComponent("Authentication blocked")}`);
    }
  } catch (error) {
    console.error("Demo callback error:", error);
    res.redirect(`/?error=${encodeURIComponent("Authentication failed")}`);
  }
});

/**
 * GET /demo/mfa-callback
 * Authsignal redirects here after MFA challenge completion.
 * Validates the token and upgrades the session.
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

    // Find and upgrade the existing session
    const sessionId = req.cookies?.["session_id"];
    if (sessionId) {
      const session = sessionStore.get(sessionId);
      if (session) {
        session.mfaVerified = true;
        session.mfaMethod = validation.verificationMethod;
        delete session._mfaToken;
        sessionStore.set(sessionId, session);
      }
    }

    res.redirect("/dashboard.html");
  } catch (error) {
    console.error("MFA callback error:", error);
    res.redirect(`/?error=${encodeURIComponent("MFA validation failed")}`);
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
router.post("/mfa-settings", async (req: Request, res: Response) => {
  try {
    const sessionId = req.cookies?.["session_id"];
    if (!sessionId) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }

    const session = sessionStore.get(sessionId);
    if (!session) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }

    const result = await authsignalService.trackAction({
      userId: session.userId,
      action: "manageSettings",
      attributes: {
        redirectUrl: `${config.app.baseUrl}/dashboard.html`,
        email: session.email,
      },
    });

    res.json({
      settingsUrl: result.url,
      token: result.token,
    });
  } catch (error) {
    console.error("MFA settings error:", error);
    res.status(500).json({ error: "Failed to load MFA settings" });
  }
});

/**
 * POST /demo/logout
 */
router.post("/logout", (req: Request, res: Response) => {
  const sessionId = req.cookies?.["session_id"];
  if (sessionId) {
    sessionStore.delete(sessionId);
  }
  res.clearCookie("session_id");
  res.json({ success: true });
});

export default router;
