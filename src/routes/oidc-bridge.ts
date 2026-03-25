/**
 * OIDC Bridge Routes
 *
 * These routes enable PingOne to use Authsignal as an external OIDC MFA provider.
 *
 * Flow:
 * 1. User authenticates with PingOne (username/password)
 * 2. PingOne sign-on policy includes an "External IdP" step pointing here
 * 3. /oidc/initiate - receives the PingOne user context, calls Authsignal init-auth
 * 4. Redirects user to Authsignal OIDC /auth for MFA challenge
 * 5. /oidc/callback - receives the auth code from Authsignal, exchanges for tokens
 * 6. Validates the MFA result and redirects back to PingOne to resume the flow
 */

import { Router, type Request, type Response } from "express";
import { config } from "../config.js";
import * as authsignalService from "../services/authsignal.js";
import {
  generateState,
  generateNonce,
  generateCodeVerifier,
  generateCodeChallenge,
} from "../utils/crypto.js";
import { decodeTokenUnsafe } from "../utils/jwt.js";
import type { OidcBridgeSession } from "../types/index.js";

const router = Router();

// In-memory store for OIDC bridge sessions (use Redis in production)
const bridgeSessions = new Map<string, OidcBridgeSession>();

// Clean up expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, session] of bridgeSessions) {
    if (now - session.createdAt > 10 * 60 * 1000) {
      bridgeSessions.delete(key);
    }
  }
}, 5 * 60 * 1000);

/**
 * POST /oidc/initiate
 *
 * Called by PingOne (via browser redirect) when the sign-on policy
 * requires an external MFA step. PingOne passes the user's context
 * as query parameters or in the ID token hint.
 *
 * Alternatively, this can be called directly by your app to start
 * the Authsignal MFA flow in an OIDC-compliant way.
 */
router.get("/initiate", async (req: Request, res: Response) => {
  try {
    const {
      user_id,
      email,
      phone,
      action = "mfa",
      flow_id,
      id_token_hint,
    } = req.query as Record<string, string>;

    // Extract user info from either query params or ID token hint
    let userId = user_id;
    let userEmail = email;

    if (id_token_hint && !userId) {
      const claims = decodeTokenUnsafe(id_token_hint);
      if (claims) {
        userId = claims.sub ?? userId;
        userEmail = (claims as any).email ?? userEmail;
      }
    }

    if (!userId) {
      res.status(400).json({ error: "user_id is required" });
      return;
    }

    // Generate PKCE and state for the Authsignal OIDC flow
    const state = generateState();
    const nonce = generateNonce();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    const callbackUrl = `${config.app.baseUrl}/oidc/callback`;

    // Call Authsignal's init-auth to get a scoped token
    const initResult = await authsignalService.oidcInitAuth({
      userId,
      action,
      email: userEmail,
      phoneNumber: phone,
    });

    // Store session data for the callback
    bridgeSessions.set(state, {
      state,
      nonce,
      codeVerifier,
      pingOneUserId: userId,
      pingOneSessionId: flow_id,
      action,
      redirectUri: callbackUrl,
      createdAt: Date.now(),
    });

    // Build the Authsignal OIDC authorization URL
    const authUrl = new URL(`${config.authsignal.oidcUrl}/oidc/auth`);
    authUrl.searchParams.set("client_id", config.authsignal.tenantId);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("redirect_uri", callbackUrl);
    authUrl.searchParams.set("scope", "openid");
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("nonce", nonce);
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("token", initResult.token);

    res.redirect(authUrl.toString());
  } catch (error) {
    console.error("OIDC initiate error:", error);
    res.status(500).json({ error: "Failed to initiate MFA challenge" });
  }
});

/**
 * GET /oidc/callback
 *
 * Receives the authorization code from Authsignal after the user
 * completes (or fails) the MFA challenge.
 */
router.get("/callback", async (req: Request, res: Response) => {
  try {
    const { code, state, error, error_description } = req.query as Record<
      string,
      string
    >;

    if (error) {
      console.error("Authsignal OIDC error:", error, error_description);
      res.status(400).json({
        error: "MFA challenge failed",
        detail: error_description || error,
      });
      return;
    }

    if (!state || !code) {
      res.status(400).json({ error: "Missing state or code" });
      return;
    }

    // Retrieve and validate the bridge session
    const session = bridgeSessions.get(state);
    if (!session) {
      res.status(400).json({ error: "Invalid or expired state" });
      return;
    }
    bridgeSessions.delete(state);

    // Exchange the code for tokens at Authsignal's OIDC token endpoint
    const tokens = await authsignalService.oidcTokenExchange({
      code,
      redirectUri: session.redirectUri,
      codeVerifier: session.codeVerifier,
    });

    // Decode the access token to get the MFA result
    const claims = decodeTokenUnsafe(tokens.access_token);
    if (!claims) {
      res.status(500).json({ error: "Failed to decode Authsignal token" });
      return;
    }

    const actionState = (claims as any).action_state as string;
    const verificationMethod = (claims as any).action_verification_method;
    const mfaSucceeded =
      actionState === "CHALLENGE_SUCCEEDED" || actionState === "ALLOW";

    // If PingOne flow_id was provided, redirect back to PingOne to resume
    if (session.pingOneSessionId) {
      const resumeUrl = new URL(
        `${config.pingone.authBaseUrl}/${config.pingone.environmentId}/as/resume`
      );
      resumeUrl.searchParams.set("flowId", session.pingOneSessionId);

      if (mfaSucceeded) {
        res.redirect(resumeUrl.toString());
      } else {
        res.status(403).json({
          error: "MFA verification failed",
          state: actionState,
        });
      }
      return;
    }

    // Standalone mode: return the result directly
    res.json({
      success: mfaSucceeded,
      userId: session.pingOneUserId,
      action: session.action,
      state: actionState,
      verificationMethod,
    });
  } catch (error) {
    console.error("OIDC callback error:", error);
    res.status(500).json({ error: "Failed to process MFA callback" });
  }
});

export default router;
