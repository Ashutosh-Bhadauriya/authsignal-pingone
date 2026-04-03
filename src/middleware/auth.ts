import { type Request, type Response, type NextFunction } from "express";
import { config } from "../config.js";
import { timingSafeEqual } from "../utils/crypto.js";

/**
 * Authenticates DaVinci HTTP connector requests using a shared API key.
 * The key is passed via the X-API-Key header.
 */
export function davinciApiKeyAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const apiKey = config.davinci.apiKey;
  if (!apiKey) {
    res.status(500).json({ error: "DaVinci bridge API key not configured" });
    return;
  }

  const providedKey = req.headers["x-api-key"];
  if (typeof providedKey !== "string" || !timingSafeEqual(providedKey, apiKey)) {
    res.status(401).json({ error: "Invalid API key" });
    return;
  }

  next();
}

/**
 * Validates that a session cookie exists and is not expired.
 * Attaches the session to req.appSession.
 */
export function requireSession(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const sessionId = req.signedCookies?.["session_id"];
  if (!sessionId) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }

  const session = sessionStore.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessionStore.delete(sessionId);
    res.status(401).json({ error: "Session expired" });
    return;
  }

  (req as any).appSession = session;
  next();
}

// In-memory session store (use Redis/DB in production)
export const MAX_SESSIONS = 50_000;
export const sessionStore = new Map<string, any>();

// Clean up expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, session] of sessionStore) {
    if (session.expiresAt < now) {
      sessionStore.delete(key);
    }
  }
}, 5 * 60 * 1000);
