// Minimal relying party that stands in for PingOne during manual tests.
// It receives the redirect from the bridge, exchanges the code and verifies the ID token.
// Run with: node --env-file=.env test/rp-stub.mjs   (register http://localhost:3999/cb as a redirect URI)
import http from "node:http";
import * as jose from "jose";

const PORT = 3999;
const issuer = process.env.APP_BASE_URL;
const clientId = process.env.OIDC_PROVIDER_CLIENT_ID;
const clientSecret = process.env.OIDC_PROVIDER_CLIENT_SECRET;
const redirectUri = `http://localhost:${PORT}/cb`;
const jwks = jose.createRemoteJWKSet(new URL(`${issuer}/oidc-provider/jwks`));

const escapeHtml = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, redirectUri);
    if (url.pathname !== "/cb") {
      res.writeHead(404).end();
      return;
    }
    let result;
    try {
      const error = url.searchParams.get("error");
      if (error) {
        result = { outcome: "ERROR_FROM_PROVIDER", error, error_description: url.searchParams.get("error_description"), state: url.searchParams.get("state") };
      } else {
        const tokenRes = await fetch(`${issuer}/oidc-provider/token`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
          },
          body: new URLSearchParams({ grant_type: "authorization_code", code: url.searchParams.get("code") ?? "", redirect_uri: redirectUri }),
        });
        const tokens = await tokenRes.json();
        if (!tokenRes.ok) throw new Error(`token endpoint ${tokenRes.status}: ${JSON.stringify(tokens)}`);
        const { payload } = await jose.jwtVerify(tokens.id_token, jwks, { issuer, audience: clientId });
        result = { outcome: "ID_TOKEN_VERIFIED", state: url.searchParams.get("state"), claims: payload };
      }
    } catch (error) {
      result = { outcome: "RP_FAILURE", message: error.message };
    }
    console.log(JSON.stringify(result));
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<!doctype html><title>RP stub</title><h1>${escapeHtml(result.outcome)}</h1><pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>`);
  })
  .listen(PORT, () => console.log(`RP stub listening on ${redirectUri}`));
