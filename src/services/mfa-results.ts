import type { VerificationMethod } from "../types/index.js";

const MFA_RESULT_TTL_MS = 10 * 60 * 1000;
const MAX_MFA_RESULTS = 10_000;

export interface MfaCompletionResult {
  callbackState: string;
  success: boolean;
  userId: string;
  action: string;
  state: string;
  verificationMethod?: VerificationMethod;
  error?: string;
  createdAt: number;
}

const mfaResults = new Map<string, MfaCompletionResult>();

function cleanupExpiredMfaResults(): void {
  const now = Date.now();
  for (const [key, result] of mfaResults) {
    if (now - result.createdAt > MFA_RESULT_TTL_MS) {
      mfaResults.delete(key);
    }
  }
}

export function recordMfaResult(
  result: Omit<MfaCompletionResult, "createdAt">
): boolean {
  cleanupExpiredMfaResults();

  if (mfaResults.size >= MAX_MFA_RESULTS) {
    return false;
  }

  mfaResults.set(result.callbackState, {
    ...result,
    createdAt: Date.now(),
  });
  return true;
}

export function consumeMfaResult(
  callbackState: string
): MfaCompletionResult | undefined {
  const result = mfaResults.get(callbackState);
  if (!result) {
    return undefined;
  }

  mfaResults.delete(callbackState);

  if (Date.now() - result.createdAt > MFA_RESULT_TTL_MS) {
    return undefined;
  }

  return result;
}

setInterval(cleanupExpiredMfaResults, 5 * 60 * 1000);
