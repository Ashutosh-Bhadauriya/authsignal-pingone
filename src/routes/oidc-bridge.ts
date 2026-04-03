/**
 * MFA Federation Bridge Routes
 *
 * A redirect-based bridge that lets PingOne sign-on flows delegate the MFA
 * step to Authsignal's OIDC-based MFA, then resume the PingOne flow.
 *
 * This bridge is an OIDC *client* to Authsignal (not an OIDC provider).
 * PingOne triggers it via a browser redirect (e.g. from a DaVinci flow
 * redirect node or a custom sign-on policy step), NOT via the PingOne
 * "External IdP" admin configuration.
 *
 * Flow:
 * 1. User authenticates with PingOne (username/password)
 * 2. PingOne redirects browser to /oidc/initiate with user context
 * 3. Bridge calls Authsignal /init-auth, then redirects to Authsignal OIDC /auth
 * 4. User completes MFA in Authsignal's UI
 * 5. Authsignal redirects to /oidc/callback with an authorization code
 * 6. Bridge exchanges code, verifies the ID token, validates the MFA result
 * 7. Bridge redirects back to PingOne /as/resume to continue the sign-on flow
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
import {
  SAFE_IDENTIFIER_RE,
  getQueryString,
  getStringClaim,
  normalizeAction,
} from "../utils/validation.js";
import type { OidcBridgeSession } from "../types/index.js";

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
 * - PingOne sign-on policy redirect (with flow_id + id_token_hint)
 * - A customer app redirect (with callback_url + callback_state)
 * - Direct call for testing (returns JSON on completion)
 */
router.get("/initiate", async (req: Request, res: Response) => {
  try {
    const userIdParam = getQueryString(req.query.user_id);
    const emailParam = getQueryString(req.query.email);
    const phone = getQueryString(req.query.phone);
    const actionParam = getQueryString(req.query.action);
    const flowId = getQueryString(req.query.flow_id);
    const idTokenHint = getQueryString(req.query.id_token_hint);
    const callbackUrlParam = getQueryString(req.query.callback_url);
    const callbackStateParam = getQueryString(req.query.callback_state);
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
    if (flowId && callbackUrlParam) {
      res.status(400).json({ error: "flow_id and callback_url are mutually exclusive" });
      return;
    }
    if (callbackUrlParam && !callbackStateParam) {
      res.status(400).json({ error: "callback_state is required with callback_url" });
      return;
    }
    if (callbackUrlParam && !isAllowedCallbackUrl(callbackUrlParam)) {
      res.status(400).json({ error: "callback_url must be same-origin" });
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

    // Verify the token subject matches the expected user
    if (claims.sub && claims.sub !== session.pingOneUserId) {
      res.status(403).json({ error: "User mismatch in MFA response" });
      return;
    }
    if (actionCode && actionCode !== session.action) {
      res.status(403).json({ error: "Action mismatch in MFA response" });
      return;
    }

    // 1. PingOne resume flow — redirect back to PingOne
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

    // 2. Callback mode — redirect back to the caller's app
    if (session.callbackUrl) {
      const target = new URL(session.callbackUrl);
      target.searchParams.set("callback_state", session.callbackState!);
      target.searchParams.set("success", String(mfaSucceeded));
      target.searchParams.set("user_id", session.pingOneUserId);
      target.searchParams.set("action", session.action);
      if (verificationMethod) {
        target.searchParams.set("verification_method", verificationMethod);
      }
      if (!mfaSucceeded && actionState) {
        target.searchParams.set("error", actionState);
      }
      res.redirect(target.toString());
      return;
    }

    // 3. API mode — return JSON (for testing)
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
