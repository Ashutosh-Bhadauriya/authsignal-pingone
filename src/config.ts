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

export const config = {
  port: parseInt(optional("PORT", "3000"), 10),

  // ─── Authsignal ─────────────────────────────────────────────────────────
  authsignal: {
    secret: required("AUTHSIGNAL_SECRET"),
    tenantId: required("AUTHSIGNAL_TENANT_ID"),
    apiUrl: optional("AUTHSIGNAL_API_URL", "https://api.authsignal.com/v1"),
    oidcUrl: optional(
      "AUTHSIGNAL_OIDC_URL",
      "https://us-connect.authsignal.com"
    ),
  },

  // ─── PingOne ────────────────────────────────────────────────────────────
  pingone: {
    environmentId: optional("PINGONE_ENVIRONMENT_ID", ""),
    clientId: optional("PINGONE_CLIENT_ID", ""),
    clientSecret: optional("PINGONE_CLIENT_SECRET", ""),
    authBaseUrl: optional(
      "PINGONE_AUTH_BASE_URL",
      "https://auth.pingone.com"
    ),
    apiBaseUrl: optional(
      "PINGONE_API_BASE_URL",
      "https://api.pingone.com/v1"
    ),
  },

  // ─── App ────────────────────────────────────────────────────────────────
  app: {
    baseUrl: optional("APP_BASE_URL", "http://localhost:3000"),
    sessionSecret: required("SESSION_SECRET"),
    sessionMaxAge: parseInt(optional("SESSION_MAX_AGE", "3600"), 10),
    trustProxy: parseTrustProxy(optional("TRUST_PROXY", "false")),
  },

  // ─── DaVinci API Key (for bridge auth) ─────────────────────────────────
  davinci: {
    apiKey: optional("DAVINCI_BRIDGE_API_KEY", ""),
  },
} as const;

export type Config = typeof config;
