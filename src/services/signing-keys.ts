/**
 * OIDC Provider Signing Keys
 *
 * Generates an ephemeral RSA key pair on startup for signing ID tokens
 * issued by the bridge's OIDC provider. Keys are regenerated on each
 * restart — DaVinci fetches the JWKS fresh for each verification.
 */

import { randomBytes } from "node:crypto";
import * as jose from "jose";
import { config } from "../config.js";

let privateKey: jose.KeyLike;
let publicJwk: jose.JWK;
let kid: string;

export async function initSigningKeys(): Promise<void> {
  const keyPair = await jose.generateKeyPair("RS256", {
    modulusLength: 2048,
  });
  privateKey = keyPair.privateKey;

  kid = randomBytes(16).toString("hex");
  const exported = await jose.exportJWK(keyPair.publicKey);
  publicJwk = { ...exported, kid, use: "sig", alg: "RS256" };
}

export function getJwks(): { keys: jose.JWK[] } {
  return { keys: [publicJwk] };
}

export async function signIdToken(claims: {
  sub: string;
  aud: string;
  nonce?: string;
  action_state: string;
  action_verification_method?: string;
  action: string;
}): Promise<string> {
  const builder = new jose.SignJWT({
    nonce: claims.nonce,
    action_state: claims.action_state,
    action_verification_method: claims.action_verification_method,
    action: claims.action,
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(config.app.baseUrl)
    .setSubject(claims.sub)
    .setAudience(claims.aud)
    .setIssuedAt()
    .setExpirationTime("5m");

  return builder.sign(privateKey);
}
