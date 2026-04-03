import { randomBytes } from "node:crypto";
import "dotenv/config";

const required = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
};

const optional = (name: string, fallback: string): string =>
  process.env[name] || fallback;

const parseTrustProxy = (value: string): boolean | number | string => {
  if (value === "true") return true;
  if (value === "false") return false;

  const parsed = Number.parseInt(value, 10);
  if (!Number.isNaN(parsed) && parsed.toString() === value) {
    return parsed;
  }

  return value;
};

// ─── Region → URL Mapping ─────────────────────────────────────────────────

type AuthsignalRegion = "us" | "eu" | "au" | "ca";

const AUTHSIGNAL_URLS: Record<AuthsignalRegion, { apiUrl: string; oidcUrl: string }> = {
  us: { apiUrl: "https://api.authsignal.com/v1", oidcUrl: "https://us-connect.authsignal.com" },
  eu: { apiUrl: "https://api.eu.authsignal.com/v1", oidcUrl: "https://eu-connect.authsignal.com" },
  au: { apiUrl: "https://api.au.authsignal.com/v1", oidcUrl: "https://au-connect.authsignal.com" },
  ca: { apiUrl: "https://api.ca.authsignal.com/v1", oidcUrl: "https://ca-connect.authsignal.com" },
};

type PingOneRegion = "NA" | "EU" | "CA" | "AP" | "AU";

const PINGONE_URLS: Record<PingOneRegion, { authBaseUrl: string; apiBaseUrl: string }> = {
  NA: { authBaseUrl: "https://auth.pingone.com", apiBaseUrl: "https://api.pingone.com/v1" },
  EU: { authBaseUrl: "https://auth.pingone.eu", apiBaseUrl: "https://api.pingone.eu/v1" },
  CA: { authBaseUrl: "https://auth.pingone.ca", apiBaseUrl: "https://api.pingone.ca/v1" },
  AP: { authBaseUrl: "https://auth.pingone.asia", apiBaseUrl: "https://api.pingone.asia/v1" },
  AU: { authBaseUrl: "https://auth.pingone.com.au", apiBaseUrl: "https://api.pingone.com.au/v1" },
};

function getAuthsignalUrls(): { apiUrl: string; oidcUrl: string } {
  const region = optional("AUTHSIGNAL_REGION", "us") as AuthsignalRegion;
  const urls = AUTHSIGNAL_URLS[region];
  if (!urls) {
    throw new Error(`Invalid AUTHSIGNAL_REGION: ${region}. Must be one of: ${Object.keys(AUTHSIGNAL_URLS).join(", ")}`);
  }
  return urls;
}

function getPingOneUrls(): { authBaseUrl: string; apiBaseUrl: string } {
  const region = optional("PINGONE_REGION", "NA") as PingOneRegion;
  const urls = PINGONE_URLS[region];
  if (!urls) {
    throw new Error(`Invalid PINGONE_REGION: ${region}. Must be one of: ${Object.keys(PINGONE_URLS).join(", ")}`);
  }
  return urls;
}

function getSessionSecret(): string {
  const envValue = process.env["SESSION_SECRET"];
  if (envValue) return envValue;

  console.warn("WARNING: SESSION_SECRET not set — using auto-generated value. Sessions will not survive restarts.");
  return randomBytes(32).toString("hex");
}

// ─── Config ─────────────────────────────────────────────────────────────────

const authsignalUrls = getAuthsignalUrls();
const pingoneUrls = getPingOneUrls();

export const config = {
  port: parseInt(optional("PORT", "3000"), 10),

  // ─── Authsignal ─────────────────────────────────────────────────────────
  authsignal: {
    secret: required("AUTHSIGNAL_SECRET"),
    tenantId: required("AUTHSIGNAL_TENANT_ID"),
    apiUrl: authsignalUrls.apiUrl,
    oidcUrl: authsignalUrls.oidcUrl,
  },

  // ─── PingOne ────────────────────────────────────────────────────────────
  pingone: {
    environmentId: optional("PINGONE_ENVIRONMENT_ID", ""),
    clientId: optional("PINGONE_CLIENT_ID", ""),
    clientSecret: optional("PINGONE_CLIENT_SECRET", ""),
    authBaseUrl: pingoneUrls.authBaseUrl,
    apiBaseUrl: pingoneUrls.apiBaseUrl,
  },

  // ─── App ────────────────────────────────────────────────────────────────
  app: {
    baseUrl: optional("APP_BASE_URL", "http://localhost:3000"),
    sessionSecret: getSessionSecret(),
    sessionMaxAge: 3600,
    trustProxy: parseTrustProxy(optional("TRUST_PROXY", "false")),
  },

  // ─── DaVinci API Key (for bridge auth) ─────────────────────────────────
  davinci: {
    apiKey: optional("DAVINCI_BRIDGE_API_KEY", ""),
  },

  // ─── OIDC Provider (for DaVinci OIDC connector) ──────────────────────
  oidcProvider: {
    clientId: optional("OIDC_PROVIDER_CLIENT_ID", ""),
    clientSecret: optional("OIDC_PROVIDER_CLIENT_SECRET", ""),
  },
} as const;

export type Config = typeof config;
