/**
 * Legacy MFA bridge (demo app only)
 *
 * The demo app redirects the browser here after PingOne login. The bridge runs
 * Authsignal's OIDC MFA (classic actions, via /init-auth) and redirects back to
 * the demo with a server-side result.
 *
 * PingOne and DaVinci do not call these routes. They use the standard OIDC
 * provider in ./oidc-provider.ts, which runs an Authsignal Flow.
 *
 * Flow:
 * 1. Demo app redirects the browser to /oidc/initiate with callback_url + callback_state
 * 2. Bridge calls Authsignal /init-auth, then redirects to Authsignal OIDC /auth
 * 3. User completes MFA in Authsignal's UI
 * 4. Authsignal redirects to /oidc/callback with an authorization code
 * 5. Bridge exchanges the code, verifies the ID token and records the MFA result
 * 6. Bridge redirects back to callback_url
 */

import { Router, type Request, type Response } from "express";
import { config } from "../config.js";
import * as authsignalService from "../services/authsignal.js";
import { recordMfaResult } from "../services/mfa-results.js";
import {
  generateState,
  generateCodeVerifier,
  generateCodeChallenge,
} from "../utils/crypto.js";
import { verifyAuthsignalIdToken } from "../utils/jwt.js";
import {
  SAFE_CALLBACK_STATE_RE,
  SAFE_IDENTIFIER_RE,
  getQueryString,
  getStringClaim,
  isReasonableEmail,
  isReasonablePhoneNumber,
  normalizeAction,
} from "../utils/validation.js";
import type { OidcBridgeSession, VerificationMethod } from "../types/index.js";

const router = Router();

// In-memory store for OIDC bridge sessions (use Redis in production)
const MAX_BRIDGE_SESSIONS = 10_000;
const bridgeSessions = new Map<string, OidcBridgeSession>();

function isAllowedCallbackUrl(url: string): boolean {
  try {
    const target = new URL(url);
    const app = new URL(config.app.baseUrl);
    return target.origin === app.origin;
  } catch {
    return false;
  }
}

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
 * GET /oidc/initiate
 *
 * Initiates Authsignal MFA via the OIDC federation bridge.
 *
 * Can be triggered by:
 * - The demo app (with callback_url + callback_state)
 * - Direct call for testing (returns JSON on completion)
 */
router.get("/initiate", async (req: Request, res: Response) => {
  try {
    const userIdParam = getQueryString(req.query.user_id);
    const emailParam = getQueryString(req.query.email);
    const phone = getQueryString(req.query.phone);
    const actionParam = getQueryString(req.query.action);
    const callbackUrlParam = getQueryString(req.query.callback_url);
    const callbackStateParam = getQueryString(req.query.callback_state);
    const userId = userIdParam;
    const userEmail = emailParam;

    if (!userId) {
      res.status(400).json({ error: "user_id is required" });
      return;
    }

    if (!SAFE_IDENTIFIER_RE.test(userId)) {
      res.status(400).json({ error: "Invalid user_id format" });
      return;
    }
    if (userEmail && !isReasonableEmail(userEmail)) {
      res.status(400).json({ error: "Invalid email format" });
      return;
    }
    if (phone && !isReasonablePhoneNumber(phone)) {
      res.status(400).json({ error: "Invalid phone format" });
      return;
    }
    if (callbackUrlParam && !callbackStateParam) {
      res.status(400).json({ error: "callback_state is required with callback_url" });
      return;
    }
    if (callbackStateParam && !SAFE_CALLBACK_STATE_RE.test(callbackStateParam)) {
      res.status(400).json({ error: "Invalid callback_state format" });
      return;
    }
    if (callbackUrlParam && !isAllowedCallbackUrl(callbackUrlParam)) {
      res.status(400).json({ error: "callback_url must be same-origin" });
      return;
    }

    const action = normalizeAction(actionParam);

    // Enforce max sessions to prevent memory exhaustion
    if (bridgeSessions.size >= MAX_BRIDGE_SESSIONS) {
      res.status(503).json({ error: "Service temporarily at capacity" });
      return;
    }

    // Generate PKCE and state for the Authsignal OIDC flow
    const state = generateState();
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
      codeVerifier,
      pingOneUserId: userId,
      callbackUrl: callbackUrlParam,
      callbackState: callbackStateParam,
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
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("token", initResult.token);

    res.redirect(authUrl.toString());
  } catch (error) {
    console.error("OIDC initiate error:", (error as Error).message);
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
    const code = getQueryString(req.query.code);
    const state = getQueryString(req.query.state);
    const error = getQueryString(req.query.error);

    if (error) {
      console.error("Authsignal OIDC error:", error);
      res.status(400).json({ error: "MFA challenge failed" });
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

    // Verify the Authsignal OIDC ID token (signature, issuer, audience).
    const claims = await verifyAuthsignalIdToken(
      tokens.id_token,
      config.authsignal.oidcUrl,
      config.authsignal.tenantId
    );

    const claimMap = claims as Record<string, unknown>;
    const actionState = getStringClaim(claimMap, "action_state");
    const actionCode = getStringClaim(claimMap, "action_code");
    const verificationMethod = getStringClaim(
      claimMap,
      "action_verification_method"
    );

    if (!actionState) {
      res.status(403).json({ error: "Missing action_state in Authsignal response" });
      return;
    }
    const mfaSucceeded =
      actionState === "CHALLENGE_SUCCEEDED" || actionState === "ALLOW";

    // Verify the token subject matches the expected user.
    if (!claims.sub || claims.sub !== session.pingOneUserId) {
      res.status(403).json({ error: "User mismatch in MFA response" });
      return;
    }
    if (!actionCode || actionCode !== session.action) {
      res.status(403).json({ error: "Action mismatch in MFA response" });
      return;
    }

    // 1. Callback mode — redirect back to the caller's app
    if (session.callbackUrl) {
      const stored = recordMfaResult({
        callbackState: session.callbackState!,
        success: mfaSucceeded,
        userId: session.pingOneUserId,
        action: session.action,
        state: actionState,
        verificationMethod: verificationMethod as VerificationMethod | undefined,
        error: mfaSucceeded ? undefined : actionState,
      });

      if (!stored) {
        res.status(503).json({ error: "Service temporarily at capacity" });
        return;
      }

      const target = new URL(session.callbackUrl);
      target.searchParams.set("callback_state", session.callbackState!);
      res.redirect(target.toString());
      return;
    }

    // 2. API mode — return JSON (for testing)
    res.json({
      success: mfaSucceeded,
      userId: session.pingOneUserId,
      action: session.action,
      state: actionState,
      verificationMethod,
    });
  } catch (error) {
    console.error("OIDC callback error:", (error as Error).message);
    res.status(500).json({ error: "Failed to process MFA callback" });
  }
});

export default router;
