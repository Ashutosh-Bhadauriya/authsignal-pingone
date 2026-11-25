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

const isProduction = process.env.NODE_ENV === "production";

const parseTrustProxy = (value: string): boolean | number | string => {
  if (value === "true") return true;
  if (value === "false") return false;

  const parsed = Number.parseInt(value, 10);
  if (!Number.isNaN(parsed) && parsed.toString() === value) {
    return parsed;
  }

  return value;
};

const parsePort = (value: string): number => {
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`Invalid PORT: ${value}`);
  }
  return port;
};

const parseBoolean = (name: string, fallback: boolean): boolean => {
  const value = process.env[name];
  if (!value) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`Invalid ${name}: must be true or false`);
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
  if (envValue) {
    if (Buffer.byteLength(envValue, "utf8") < 32) {
      throw new Error("SESSION_SECRET must be at least 32 bytes");
    }
    return envValue;
  }

  if (isProduction) {
    throw new Error("SESSION_SECRET must be set in production");
  }

  console.warn("WARNING: SESSION_SECRET not set — using auto-generated value. Sessions will not survive restarts.");
  return randomBytes(32).toString("hex");
}

function getAppBaseUrl(): string {
  const value = optional("APP_BASE_URL", "http://localhost:3000");
  const url = new URL(value);

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("APP_BASE_URL must use http or https");
  }
  if (url.search || url.hash) {
    throw new Error("APP_BASE_URL must not include a query string or fragment");
  }

  return url.toString().replace(/\/$/, "");
}

// ─── OIDC Provider (bridge acts as an IdP for PingOne / DaVinci) ───────────

function parseRedirectUris(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const url = new URL(entry);
      if (url.protocol !== "https:" && url.hostname !== "localhost") {
        throw new Error(`OIDC_PROVIDER_REDIRECT_URIS entries must use https: ${entry}`);
      }
      if (url.hash) {
        throw new Error(`OIDC_PROVIDER_REDIRECT_URIS entries must not include a fragment: ${entry}`);
      }
      return url.toString();
    });
}

function getOidcProviderConfig() {
  const clientId = process.env["OIDC_PROVIDER_CLIENT_ID"];
  const clientSecret = process.env["OIDC_PROVIDER_CLIENT_SECRET"];
  const redirectUris = parseRedirectUris(optional("OIDC_PROVIDER_REDIRECT_URIS", ""));

  if (clientSecret && Buffer.byteLength(clientSecret, "utf8") < 32) {
    throw new Error("OIDC_PROVIDER_CLIENT_SECRET must be at least 32 bytes");
  }

  return {
    // The provider is enabled only when a client and at least one redirect URI are configured.
    enabled: Boolean(clientId && clientSecret && redirectUris.length > 0),
    clientId,
    clientSecret,
    redirectUris,
    // Code of the Authsignal action (type FLOW) that runs the MFA step.
    flowActionCode: optional("AUTHSIGNAL_FLOW_ACTION_CODE", "pingone-mfa"),
    // Private RSA key as a JWK JSON string. Required in production.
    signingKeyJwk: process.env["OIDC_PROVIDER_SIGNING_KEY_JWK"],
    isProduction,
  };
}

// ─── DaVinci application (demo app embeds the DaVinci widget) ──────────────

function getDavinciConfig(authBaseUrl: string) {
  const environmentId = process.env["DAVINCI_ENVIRONMENT_ID"];
  const policyId = process.env["DAVINCI_POLICY_ID"];
  const apiKey = process.env["DAVINCI_API_KEY"];
  const flowId = process.env["DAVINCI_FLOW_ID"];

  // These IDs become URL path segments, so only accept the shapes DaVinci issues.
  const idPattern = /^[a-f0-9-]{32,36}$/i;
  for (const [name, value] of [
    ["DAVINCI_ENVIRONMENT_ID", environmentId],
    ["DAVINCI_POLICY_ID", policyId],
    ["DAVINCI_FLOW_ID", flowId],
  ] as const) {
    if (value && !idPattern.test(value)) {
      throw new Error(`Invalid ${name}: expected the ID shown in the DaVinci console`);
    }
  }

  const authUrl = new URL(authBaseUrl);
  return {
    // The demo app uses DaVinci when all three values are set, otherwise the legacy PingOne login.
    enabled: Boolean(environmentId && policyId && apiKey),
    environmentId,
    policyId,
    apiKey,
    // Optional: only accept signed responses from this flow.
    flowId,
    // Base URL the widget talks to, and the issuer of the tokens DaVinci signs.
    apiRoot: `${authBaseUrl}/`,
    issuer: environmentId ? `${authBaseUrl}/${environmentId}/davinci` : undefined,
    // The SDK token endpoint lives on the orchestrate-api host of the same region.
    sdkTokenUrl: environmentId
      ? `https://${authUrl.hostname.replace(/^auth\./, "orchestrate-api.")}/v1/company/${environmentId}/sdktoken`
      : undefined,
    // Where davinci.js and the flow's stylesheets are served from.
    assetsOrigin: `https://${authUrl.hostname.replace(/^auth\./, "assets.")}`,
  };
}

// ─── Config ─────────────────────────────────────────────────────────────────

const authsignalUrls = getAuthsignalUrls();
const pingoneUrls = getPingOneUrls();
const appBaseUrl = getAppBaseUrl();

export const config = {
  port: parsePort(optional("PORT", "3000")),

  // ─── Authsignal ─────────────────────────────────────────────────────────
  authsignal: {
    secret: required("AUTHSIGNAL_SECRET"),
    tenantId: required("AUTHSIGNAL_TENANT_ID"),
    // AUTHSIGNAL_API_URL overrides the region default (e.g. a mock server in tests).
    apiUrl: optional("AUTHSIGNAL_API_URL", authsignalUrls.apiUrl).replace(/\/$/, ""),
    oidcUrl: authsignalUrls.oidcUrl,
  },

  // ─── PingOne ────────────────────────────────────────────────────────────
  pingone: {
    environmentId: required("PINGONE_ENVIRONMENT_ID"),
    clientId: required("PINGONE_CLIENT_ID"),
    clientSecret: required("PINGONE_CLIENT_SECRET"),
    authBaseUrl: pingoneUrls.authBaseUrl,
    apiBaseUrl: pingoneUrls.apiBaseUrl,
  },

  // ─── DaVinci ────────────────────────────────────────────────────────────
  davinci: getDavinciConfig(pingoneUrls.authBaseUrl),

  // ─── App ────────────────────────────────────────────────────────────────
  app: {
    baseUrl: appBaseUrl,
    sessionSecret: getSessionSecret(),
    sessionMaxAge: 3600,
    trustProxy: parseTrustProxy(optional("TRUST_PROXY", "false")),
    sessionCookieSecure: parseBoolean(
      "SESSION_COOKIE_SECURE",
      new URL(appBaseUrl).protocol === "https:"
    ),
  },

  // ─── OIDC Provider ──────────────────────────────────────────────────────
  oidcProvider: getOidcProviderConfig(),
} as const;
