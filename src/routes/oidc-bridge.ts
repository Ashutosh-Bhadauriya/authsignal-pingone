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
import {
  verifyAuthsignalIdToken,
  verifyPingOneIdToken,
} from "../utils/jwt.js";
import type { OidcBridgeSession } from "../types/index.js";

const router = Router();

// In-memory store for OIDC bridge sessions (use Redis in production)
const MAX_BRIDGE_SESSIONS = 10_000;
const bridgeSessions = new Map<string, OidcBridgeSession>();
const SAFE_IDENTIFIER_RE = /^[a-zA-Z0-9_.@-]{1,128}$/;
const SAFE_ACTION_RE = /^[a-zA-Z0-9_-]{1,64}$/;

// Clean up expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, session] of bridgeSessions) {
    if (now - session.createdAt > 10 * 60 * 1000) {
      bridgeSessions.delete(key);
    }
  }
}, 5 * 60 * 1000);

function getQueryString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function normalizeAction(value: string | undefined): string {
  const action = value ?? "mfa";
  if (!SAFE_ACTION_RE.test(action)) {
    throw new Error("Invalid action");
  }
  return action;
}

function getStringClaim(
  payload: Record<string, unknown>,
  claim: string
): string | undefined {
  const value = payload[claim];
  return typeof value === "string" ? value : undefined;
}

/**
 * GET /oidc/initiate
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
    const userIdParam = getQueryString(req.query.user_id);
    const emailParam = getQueryString(req.query.email);
    const phone = getQueryString(req.query.phone);
    const actionParam = getQueryString(req.query.action);
    const flowId = getQueryString(req.query.flow_id);
    const idTokenHint = getQueryString(req.query.id_token_hint);
    const isPingOneResumeFlow = Boolean(flowId);

    // PingOne-driven resume mode must derive identity from a verified token hint.
    if (isPingOneResumeFlow && !idTokenHint) {
      res.status(400).json({ error: "id_token_hint is required when flow_id is provided" });
      return;
    }

    let userId = userIdParam;
    let userEmail = emailParam;

    if (idTokenHint) {
      try {
        const claims = await verifyPingOneIdToken(
          idTokenHint,
          config.pingone.authBaseUrl,
          config.pingone.environmentId,
          config.pingone.clientId
        );

        const hintedUserId = claims.sub;
        const hintedEmail = getStringClaim(claims as Record<string, unknown>, "email");

        if (!hintedUserId) {
          res.status(400).json({ error: "id_token_hint is missing sub" });
          return;
        }
        if (userIdParam && userIdParam !== hintedUserId) {
          res.status(400).json({ error: "user_id does not match id_token_hint" });
          return;
        }
        if (emailParam && hintedEmail && emailParam !== hintedEmail) {
          res.status(400).json({ error: "email does not match id_token_hint" });
          return;
        }

        userId = hintedUserId;
        userEmail = hintedEmail ?? userEmail;
      } catch {
        res.status(400).json({ error: "Invalid id_token_hint" });
        return;
      }
    }

    if (!userId) {
      res.status(400).json({ error: "user_id is required" });
      return;
    }

    if (!SAFE_IDENTIFIER_RE.test(userId)) {
      res.status(400).json({ error: "Invalid user_id format" });
      return;
    }
    if (flowId && !SAFE_IDENTIFIER_RE.test(flowId)) {
      res.status(400).json({ error: "Invalid flow_id format" });
      return;
    }

    const action = isPingOneResumeFlow ? "mfa" : normalizeAction(actionParam);

    // Enforce max sessions to prevent memory exhaustion
    if (bridgeSessions.size >= MAX_BRIDGE_SESSIONS) {
      res.status(503).json({ error: "Service temporarily at capacity" });
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
      pingOneSessionId: flowId,
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

    // Verify the Authsignal OIDC ID token, including the original nonce.
    const claims = await verifyAuthsignalIdToken(
      tokens.id_token,
      config.authsignal.oidcUrl,
      config.authsignal.tenantId,
      session.nonce
    );

    const claimMap = claims as Record<string, unknown>;
    const actionState = getStringClaim(claimMap, "action_state");
    const action = getStringClaim(claimMap, "action");
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

    // Verify the token subject matches the expected user
    if (claims.sub && claims.sub !== session.pingOneUserId) {
      res.status(403).json({ error: "User mismatch in MFA response" });
      return;
    }
    if (action && action !== session.action) {
      res.status(403).json({ error: "Action mismatch in MFA response" });
      return;
    }

    // If PingOne flow_id was provided, redirect back to PingOne to resume
    if (session.pingOneSessionId) {
      const resumeUrl = new URL(
        `${config.pingone.authBaseUrl}/${config.pingone.environmentId}/as/resume`
      );
      resumeUrl.searchParams.set("flowId", session.pingOneSessionId);

      if (mfaSucceeded) {
        res.redirect(resumeUrl.toString());
      } else {
        res.status(403).json({ error: "MFA verification failed" });
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
    console.error("OIDC callback error:", (error as Error).message);
    res.status(500).json({ error: "Failed to process MFA callback" });
  }
});

export default router;
