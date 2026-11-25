import { type Request, type Response, type NextFunction, type RequestHandler } from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { config } from "../config.js";

export const securityHeaders: RequestHandler = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://*.authsignal.com", "https://*.pingone.com"],
      frameSrc: ["'self'", "https://*.authsignal.com"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
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
  const appOrigin = new URL(config.app.baseUrl).origin;
  if (!origin) {
    // No origin header — could be a same-origin non-fetch request.
    // Fall back to checking Referer, then require a custom header for XHR/fetch.
    const referer = req.headers["referer"];
    if (referer) {
      try {
        const refOrigin = new URL(referer).origin;
        if (refOrigin !== appOrigin) {
          res.status(403).json({ error: "Cross-origin request blocked" });
          return;
        }
      } catch {
        res.status(403).json({ error: "Invalid referer" });
        return;
      }
      next();
      return;
    }

    if (req.headers["x-csrf-protection"] === "1") {
      next();
      return;
    }

    res.status(403).json({ error: "CSRF check failed" });
    return;
  }

  if (origin !== appOrigin) {
    res.status(403).json({ error: "Cross-origin request blocked" });
    return;
  }

  next();
}

/**
 * Rate limit for the OIDC provider endpoints. Looser than authRateLimit because
 * PingOne calls discovery, JWKS and token server-to-server from shared IPs.
 */
export const providerRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "temporarily_unavailable" },
});

/** Rate limit for the demo app's own routes (page loads call several of them). */
export const demoRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests" },
});

/**
 * Content Security Policy for the sign-in page when it hosts the DaVinci widget.
 * davinci.js is loaded from Ping's asset host, runs the scripts of Custom HTML
 * nodes and styles the flow inline, so this page needs more than the default
 * policy. Every other page keeps the strict one.
 */
export function widgetPageCsp(req: Request, res: Response, next: NextFunction): void {
  if (config.davinci.enabled && req.method === "GET" && (req.path === "/" || req.path === "/index.html")) {
    const assets = config.davinci.assetsOrigin;
    const api = new URL(config.davinci.apiRoot).origin;
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'self'",
        `script-src 'self' ${assets} 'unsafe-inline' 'unsafe-eval'`,
        `style-src 'self' 'unsafe-inline' ${assets} ${api} https://fonts.googleapis.com`,
        `font-src 'self' data: ${assets} https://fonts.gstatic.com`,
        "img-src 'self' data: https:",
        `connect-src 'self' ${api} ${assets} https://*.launchdarkly.com`,
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
      ].join("; ")
    );
  }
  next();
}
