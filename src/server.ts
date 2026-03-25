import express from "express";
import cookieParser from "cookie-parser";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { config } from "./config.js";
import { securityHeaders, apiRateLimit, authRateLimit } from "./middleware/security.js";
import oidcBridgeRouter from "./routes/oidc-bridge.js";
import davinciApiRouter from "./routes/davinci-api.js";
import demoRouter from "./routes/demo.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// ─── Global Middleware ──────────────────────────────────────────────────────

app.use(securityHeaders);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// ─── Static Files ───────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, "..", "public")));

// ─── Health Check ───────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─── OIDC Bridge (PingOne External IdP → Authsignal MFA) ───────────────────

app.use("/oidc", authRateLimit, oidcBridgeRouter);

// ─── DaVinci HTTP Connector API ─────────────────────────────────────────────

app.use("/davinci", apiRateLimit, davinciApiRouter);

// ─── Demo Application ───────────────────────────────────────────────────────

app.use("/demo", authRateLimit, demoRouter);

// ─── Start Server ───────────────────────────────────────────────────────────

app.listen(config.port, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  Authsignal + PingOne Integration Server                     ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Demo UI:        ${config.app.baseUrl.padEnd(40)}║
║  OIDC Bridge:    ${(config.app.baseUrl + '/oidc/initiate').padEnd(40)}║
║  DaVinci API:    ${(config.app.baseUrl + '/davinci/mfa/init').padEnd(40)}║
║  Health Check:   ${(config.app.baseUrl + '/health').padEnd(40)}║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});

export default app;
