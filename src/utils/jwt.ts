import * as jose from "jose";

let pingOneJwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;
let authsignalJwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;

function getPingOneJwks(
  authBaseUrl: string,
  environmentId: string
): ReturnType<typeof jose.createRemoteJWKSet> {
  if (!pingOneJwks) {
    const jwksUri = new URL(
      `/${environmentId}/as/jwks`,
      authBaseUrl
    );
    pingOneJwks = jose.createRemoteJWKSet(jwksUri);
  }
  return pingOneJwks;
}

function getAuthsignalJwks(
  oidcUrl: string
): ReturnType<typeof jose.createRemoteJWKSet> {
  if (!authsignalJwks) {
    const jwksUri = new URL("/oidc/.well-known/jwks", oidcUrl);
    authsignalJwks = jose.createRemoteJWKSet(jwksUri);
  }
  return authsignalJwks;
}

function getAuthsignalIssuer(oidcUrl: string): string {
  return new URL(oidcUrl).origin;
}

export async function verifyPingOneIdToken(
  idToken: string,
  authBaseUrl: string,
  environmentId: string,
  clientId: string,
  nonce?: string
): Promise<jose.JWTPayload> {
  const jwks = getPingOneJwks(authBaseUrl, environmentId);
  const issuer = `${authBaseUrl}/${environmentId}/as`;

  const { payload } = await jose.jwtVerify(idToken, jwks, {
    issuer,
    audience: clientId,
    clockTolerance: 30,
  });

  if (nonce && payload.nonce !== nonce) {
    throw new Error("ID token nonce mismatch");
  }

  return payload;
}

export async function verifyAuthsignalIdToken(
  idToken: string,
  oidcUrl: string,
  tenantId: string
): Promise<jose.JWTPayload> {
  // Authsignal's OIDC does not echo the `nonce` claim in the ID token, so we
  // cannot round-trip verify it here. Replay protection comes from the
  // one-time `state` (consumed on callback), PKCE `code_verifier`, the short
  // ID-token TTL, and the `sub`/`action_code` checks performed by the caller.
  const jwks = getAuthsignalJwks(oidcUrl);

  const { payload } = await jose.jwtVerify(idToken, jwks, {
    issuer: getAuthsignalIssuer(oidcUrl),
    audience: tenantId,
    clockTolerance: 30,
  });

  return payload;
}

