/**
 * DaVinci API Bridge Routes
 *
 * REST endpoints designed to be called by PingOne DaVinci flows
 * via the HTTP connector. These provide a clean interface for
 * DaVinci to interact with Authsignal for MFA and passwordless.
 *
 * DaVinci Flow Pattern:
 * 1. User authenticates with PingOne (username/password)
 * 2. DaVinci flow reaches HTTP connector node
 * 3. POST /davinci/mfa/init - initiates Authsignal MFA challenge
 * 4. DaVinci redirects user to Authsignal pre-built UI (challengeUrl)
 * 5. User completes MFA, redirected back to DaVinci flow
 * 6. POST /davinci/mfa/verify - validates the challenge result
 * 7. DaVinci flow continues based on verification result
 */

import { Router, type Request, type Response } from "express";
import { davinciApiKeyAuth } from "../middleware/auth.js";
import * as authsignalService from "../services/authsignal.js";
import type {
  DaVinciMfaInitRequest,
  DaVinciMfaInitResponse,
  DaVinciMfaVerifyRequest,
  DaVinciMfaVerifyResponse,
} from "../types/index.js";

const router = Router();

// All DaVinci bridge endpoints require API key auth
router.use(davinciApiKeyAuth);

/**
 * POST /davinci/mfa/init
 *
 * Called by DaVinci HTTP connector to initiate an MFA challenge.
 * Returns the challenge URL that DaVinci should redirect the user to.
 */
router.post("/mfa/init", async (req: Request, res: Response) => {
  try {
    const body = req.body as DaVinciMfaInitRequest;

    if (!body.userId) {
      res.status(400).json({ error: "userId is required" });
      return;
    }
    if (!body.redirectUrl) {
      res.status(400).json({ error: "redirectUrl is required" });
      return;
    }

    const result = await authsignalService.trackAction({
      userId: body.userId,
      action: body.action || "mfa",
      attributes: {
        redirectUrl: body.redirectUrl,
        email: body.email,
        phoneNumber: body.phoneNumber,
        ipAddress: body.ipAddress,
        userAgent: body.userAgent,
        custom: body.custom,
      },
    });

    const response: DaVinciMfaInitResponse = {
      challengeRequired: result.state === "CHALLENGE_REQUIRED",
      state: result.state,
      challengeUrl: result.url,
      token: result.token,
      idempotencyKey: result.idempotencyKey,
      isEnrolled: result.isEnrolled,
      enrolledMethods: result.enrolledVerificationMethods,
    };

    res.json(response);
  } catch (error) {
    console.error("DaVinci MFA init error:", error);
    res.status(500).json({ error: "Failed to initiate MFA challenge" });
  }
});

/**
 * POST /davinci/mfa/verify
 *
 * Called by DaVinci HTTP connector after the user returns from
 * the Authsignal pre-built UI. Validates the challenge token.
 */
router.post("/mfa/verify", async (req: Request, res: Response) => {
  try {
    const body = req.body as DaVinciMfaVerifyRequest;

    if (!body.token) {
      res.status(400).json({ error: "token is required" });
      return;
    }

    const result = await authsignalService.validateChallenge(body.token);

    const response: DaVinciMfaVerifyResponse = {
      isValid: result.isValid,
      state: result.state,
      userId: result.userId,
      action: result.actionCode,
      verificationMethod: result.verificationMethod,
    };

    res.json(response);
  } catch (error) {
    console.error("DaVinci MFA verify error:", error);
    res.status(500).json({ error: "Failed to verify MFA challenge" });
  }
});

/**
 * GET /davinci/user/:userId/enrollment
 *
 * Called by DaVinci to check if a user has MFA authenticators
 * enrolled with Authsignal. Useful for conditional MFA flows.
 */
router.get(
  "/user/:userId/enrollment",
  async (req: Request, res: Response) => {
    try {
      const { userId } = req.params;

      const uid = Array.isArray(userId) ? userId[0] : userId;
      const [user, authenticators] = await Promise.all([
        authsignalService.getUser(uid),
        authsignalService.getAuthenticators(uid),
      ]);

      res.json({
        userId,
        isEnrolled: user?.isEnrolled ?? false,
        enrolledVerificationMethods: user?.enrolledVerificationMethods ?? [],
        authenticators: authenticators ?? [],
      });
    } catch (error) {
      console.error("DaVinci enrollment check error:", error);
      res.status(500).json({ error: "Failed to check enrollment" });
    }
  }
);

/**
 * POST /davinci/passwordless/init
 *
 * Initiates a passwordless authentication flow via Authsignal.
 * DaVinci can call this instead of the standard PingOne password
 * authentication, enabling passkey-first login.
 */
router.post("/passwordless/init", async (req: Request, res: Response) => {
  try {
    const { userId, email, redirectUrl } = req.body as {
      userId?: string;
      email?: string;
      redirectUrl: string;
    };

    if (!redirectUrl) {
      res.status(400).json({ error: "redirectUrl is required" });
      return;
    }
    if (!userId && !email) {
      res.status(400).json({ error: "userId or email is required" });
      return;
    }

    const effectiveUserId = userId || email!;

    const result = await authsignalService.trackAction({
      userId: effectiveUserId,
      action: "signIn",
      attributes: {
        redirectUrl,
        email,
      },
    });

    res.json({
      state: result.state,
      challengeUrl: result.url,
      token: result.token,
      idempotencyKey: result.idempotencyKey,
      isEnrolled: result.isEnrolled,
      enrolledMethods: result.enrolledVerificationMethods,
    });
  } catch (error) {
    console.error("DaVinci passwordless init error:", error);
    res.status(500).json({ error: "Failed to initiate passwordless flow" });
  }
});

export default router;
