import express, { type ErrorRequestHandler } from "express";
import cookieParser from "cookie-parser";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { config } from "./config.js";
import { securityHeaders, authRateLimit, csrfOriginCheck } from "./middleware/security.js";
import oidcBridgeRouter from "./routes/oidc-bridge.js";
import demoRouter from "./routes/demo.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Trust proxy handling must match the deployed proxy chain.
app.set("trust proxy", config.app.trustProxy);
app.disable("x-powered-by");

// ─── Global Middleware ──────────────────────────────────────────────────────

app.use(securityHeaders);
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb", parameterLimit: 20 }));
app.use(cookieParser(config.app.sessionSecret));

// ─── Static Files ───────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, "..", "public")));

// ─── Health Check ───────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─── MFA Federation Bridge (PingOne → Authsignal OIDC MFA) ─────────────────

app.use("/oidc", authRateLimit, oidcBridgeRouter);

// ─── Demo Application ───────────────────────────────────────────────────────

app.use("/demo", authRateLimit, csrfOriginCheck, demoRouter);

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  const message = err instanceof Error ? err.message : "Unknown error";
  console.error("Unhandled error:", message);
  res.status(500).json({ error: "Internal server error" });
};

app.use(errorHandler);

// ─── Start Server ───────────────────────────────────────────────────────────

app.listen(config.port, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  Authsignal + PingOne Integration Server                     ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Demo UI:        ${config.app.baseUrl.padEnd(40)}║
║  MFA Bridge:     ${(config.app.baseUrl + '/oidc/initiate').padEnd(40)}║
║  Health Check:   ${(config.app.baseUrl + '/health').padEnd(40)}║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});

export default app;
