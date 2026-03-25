import { randomBytes, createHash, timingSafeEqual as cryptoTimingSafeEqual } from "node:crypto";

export function generateState(): string {
  return randomBytes(32).toString("base64url");
}

export function generateNonce(): string {
  return randomBytes(32).toString("base64url");
}

export function generateCodeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

export function generateCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function generateSessionId(): string {
  return randomBytes(32).toString("hex");
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return cryptoTimingSafeEqual(bufA, bufB);
}
