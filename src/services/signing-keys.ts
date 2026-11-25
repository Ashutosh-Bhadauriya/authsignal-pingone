/**
 * OIDC Provider Signing Keys
 *
 * Holds the RSA key the bridge signs ID tokens with. PingOne caches the JWKS,
 * so the key has to survive restarts:
 *
 * - Production: OIDC_PROVIDER_SIGNING_KEY_JWK (private RSA JWK as JSON) is required.
 * - Development: if the variable is unset, a key is generated once and stored in
 *   `.oidc-signing-key.json` (gitignored) next to the working directory.
 */

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import * as jose from "jose";
import { config } from "../config.js";

const DEV_KEY_FILE = path.resolve(process.cwd(), ".oidc-signing-key.json");
const ALG = "RS256";
const ID_TOKEN_TTL_SECONDS = 300;

let privateKey: jose.KeyLike | Uint8Array | undefined;
let publicJwk: jose.JWK | undefined;
let kid: string | undefined;

async function loadPrivateJwk(): Promise<jose.JWK> {
  if (config.oidcProvider.signingKeyJwk) {
    return JSON.parse(config.oidcProvider.signingKeyJwk) as jose.JWK;
  }

  if (config.oidcProvider.isProduction) {
    throw new Error("OIDC_PROVIDER_SIGNING_KEY_JWK must be set in production");
  }

  try {
    return JSON.parse(await readFile(DEV_KEY_FILE, "utf8")) as jose.JWK;
  } catch {
    const { privateKey: generated } = await jose.generateKeyPair(ALG, {
      modulusLength: 2048,
      extractable: true,
    });
    const jwk = await jose.exportJWK(generated);
    await writeFile(DEV_KEY_FILE, JSON.stringify(jwk), { mode: 0o600 });
    console.warn(`Generated a development OIDC signing key at ${DEV_KEY_FILE}`);
    return jwk;
  }
}

export async function initSigningKeys(): Promise<void> {
  const privateJwk = await loadPrivateJwk();
  if (privateJwk.kty !== "RSA" || !privateJwk.d) {
    throw new Error("OIDC signing key must be a private RSA JWK");
  }

  const { kty, n, e } = privateJwk;
  // RFC 7638 thumbprint, so the kid is stable for a given key.
  kid = createHash("sha256")
    .update(JSON.stringify({ e, kty, n }))
    .digest("base64url");

  privateKey = await jose.importJWK(privateJwk, ALG);
  publicJwk = { kty, n, e, kid, use: "sig", alg: ALG };
}

export function getJwks(): { keys: jose.JWK[] } {
  if (!publicJwk) throw new Error("Signing keys are not initialised");
  return { keys: [publicJwk] };
}

export interface IdTokenClaims {
  sub: string;
  aud: string;
  nonce?: string;
  authTime: number;
  acr?: string;
  amr: string[];
  verificationMethods: string[];
}

export async function signIdToken(claims: IdTokenClaims): Promise<string> {
  if (!privateKey || !kid) throw new Error("Signing keys are not initialised");

  return new jose.SignJWT({
    nonce: claims.nonce,
    auth_time: claims.authTime,
    acr: claims.acr,
    amr: claims.amr,
    authsignal_verification_methods: claims.verificationMethods,
  })
    .setProtectedHeader({ alg: ALG, kid, typ: "JWT" })
    .setIssuer(config.app.baseUrl)
    .setSubject(claims.sub)
    .setAudience(claims.aud)
    .setIssuedAt()
    .setExpirationTime(`${ID_TOKEN_TTL_SECONDS}s`)
    .sign(privateKey);
}

export { ID_TOKEN_TTL_SECONDS };
