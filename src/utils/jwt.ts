import * as jose from "jose";

let pingOneJwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;

export function getPingOneJwks(
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

export async function verifyPingOneIdToken(
  idToken: string,
  authBaseUrl: string,
  environmentId: string,
  clientId: string
): Promise<jose.JWTPayload> {
  const jwks = getPingOneJwks(authBaseUrl, environmentId);
  const issuer = `${authBaseUrl}/${environmentId}/as`;

  const { payload } = await jose.jwtVerify(idToken, jwks, {
    issuer,
    audience: clientId,
    clockTolerance: 30,
  });

  return payload;
}

export async function verifyPingOneAccessToken(
  accessToken: string,
  authBaseUrl: string,
  environmentId: string
): Promise<jose.JWTPayload> {
  const jwks = getPingOneJwks(authBaseUrl, environmentId);
  const issuer = `${authBaseUrl}/${environmentId}/as`;

  const { payload } = await jose.jwtVerify(accessToken, jwks, {
    issuer,
    clockTolerance: 30,
  });

  return payload;
}

export function decodeTokenUnsafe(token: string): jose.JWTPayload | null {
  try {
    return jose.decodeJwt(token);
  } catch {
    return null;
  }
}
