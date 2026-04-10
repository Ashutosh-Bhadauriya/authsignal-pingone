import { type Request, type Response, type NextFunction } from "express";
import type { AppSession } from "../types/index.js";

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
export const sessionStore = new Map<string, AppSession>();

// Clean up expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, session] of sessionStore) {
    if (session.expiresAt < now) {
      sessionStore.delete(key);
    }
  }
}, 5 * 60 * 1000);
