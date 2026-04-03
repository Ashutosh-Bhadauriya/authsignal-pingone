export const SAFE_IDENTIFIER_RE = /^[a-zA-Z0-9_.@-]{1,128}$/;
export const SAFE_ACTION_RE = /^[a-zA-Z0-9_-]{1,64}$/;

export function getQueryString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function getStringClaim(
  payload: Record<string, unknown>,
  claim: string
): string | undefined {
  const value = payload[claim];
  return typeof value === "string" ? value : undefined;
}

export function normalizeAction(value: string | undefined): string {
  const action = value ?? "mfa";
  if (!SAFE_ACTION_RE.test(action)) {
    throw new Error("Invalid action");
  }
  return action;
}
