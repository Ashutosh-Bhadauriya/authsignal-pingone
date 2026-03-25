import { randomBytes, createHash, createHmac, timingSafeEqual as cryptoTimingSafeEqual } from "node:crypto";

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

/**
 * Constant-time string comparison using HMAC to avoid length leaks.
 * Both values are HMAC'd first so the comparison is always fixed-length.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const key = randomBytes(32);
  const hmacA = createHmac("sha256", key).update(a).digest();
  const hmacB = createHmac("sha256", key).update(b).digest();
  return cryptoTimingSafeEqual(hmacA, hmacB);
}
