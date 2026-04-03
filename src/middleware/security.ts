import { type Request, type Response, type NextFunction, type RequestHandler } from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { config } from "../config.js";

export const securityHeaders: RequestHandler = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://*.authsignal.com", "https://*.pingone.com", "https://cdn.jsdelivr.net"],
      frameSrc: ["'self'", "https://*.authsignal.com"],
    },
  },
  crossOriginEmbedderPolicy: false,
});

export const apiRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});

export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many authentication attempts" },
});

/**
 * CSRF protection for state-mutating requests.
 * Checks that the Origin header matches the app's own origin.
 * GET/HEAD/OPTIONS are exempt (safe methods).
 */
export function csrfOriginCheck(req: Request, res: Response, next: NextFunction): void {
  const safeMethods = ["GET", "HEAD", "OPTIONS"];
  if (safeMethods.includes(req.method)) {
    next();
    return;
  }

  const origin = req.headers["origin"];
  if (!origin) {
    // No origin header — could be a same-origin non-fetch request.
    // Fall back to checking Referer if present.
    const referer = req.headers["referer"];
    if (referer) {
      try {
        const refOrigin = new URL(referer).origin;
        const appOrigin = new URL(config.app.baseUrl).origin;
        if (refOrigin !== appOrigin) {
          res.status(403).json({ error: "Cross-origin request blocked" });
          return;
        }
      } catch {
        res.status(403).json({ error: "Invalid referer" });
        return;
      }
    }
    next();
    return;
  }

  const appOrigin = new URL(config.app.baseUrl).origin;
  if (origin !== appOrigin) {
    res.status(403).json({ error: "Cross-origin request blocked" });
    return;
  }

  next();
}
