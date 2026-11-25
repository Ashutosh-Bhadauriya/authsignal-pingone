// End-to-end test of the OIDC provider against a mock Authsignal Flows API.
// Run with: npm run test:e2e
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import assert from "node:assert/strict";
import * as jose from "jose";

const MOCK_PORT = 4611;
const APP_PORT = 4610;
const BASE = `http://localhost:${APP_PORT}`;
const CLIENT_ID = "pingone-test-client";
const CLIENT_SECRET = randomBytes(32).toString("hex");
const REDIRECT_URI = "https://auth.pingone.com/test-env/rp/callback/openid_connect";
const ACTION = "pingone-mfa";

// ─── Mock Authsignal ─────────────────────────────────────────────────────────
const flows = new Map(); // challengeToken -> { userId, state, used }
let lastStart;
const mock = http.createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    const body = raw ? JSON.parse(raw) : {};
    const send = (status, json) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(json));
    };
    const expectedAuth = `Basic ${Buffer.from("test-secret:").toString("base64")}`;
    if (req.headers.authorization !== expectedAuth) return send(401, {});
    if (req.url === "/v1/flows") {
      lastStart = body;
      const token = randomBytes(16).toString("hex");
      flows.set(token, { userId: body.user.userId, outcome: "pending" });
      return send(200, {
        challengeId: "c1",
        challengeToken: token,
        challengeUrl: `https://mfa.example.test/?challenge_token=${token}&redirect_url=${encodeURIComponent(body.redirectUrl)}`,
        action: { state: "CHALLENGE_REQUIRED" },
      });
    }
    if (req.url === "/v1/flows/verify") {
      const flow = flows.get(body.challengeToken);
      if (!flow || flow.used || body.actionCode !== ACTION) return send(400, { error: "invalid" });
      flow.used = true;
      if (flow.outcome === "success")
        return send(200, {
          challengeId: "c1",
          user: { userId: flow.userId },
          action: { state: "CHALLENGE_SUCCEEDED", completedSteps: [{ stepType: "VERIFICATION", verificationMethod: "PASSKEY" }] },
        });
      if (flow.outcome === "nostep")
        return send(200, { challengeId: "c1", user: { userId: flow.userId }, action: { state: "CHALLENGE_SUCCEEDED", completedSteps: [] } });
      return send(200, { challengeId: "c1", user: { userId: flow.userId }, action: { state: "CHALLENGE_FAILED" } });
    }
    send(404, {});
  });
});
await new Promise((r) => mock.listen(MOCK_PORT, r));

// ─── App under test ──────────────────────────────────────────────────────────
const signingKey = await jose.exportJWK((await jose.generateKeyPair("RS256", { extractable: true })).privateKey);
const app = spawn("npx", ["tsx", "src/server.ts"], {
  env: {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    DOTENV_CONFIG_PATH: "/dev/null",
    PORT: String(APP_PORT),
    APP_BASE_URL: BASE,
    SESSION_SECRET: randomBytes(32).toString("hex"),
    AUTHSIGNAL_SECRET: "test-secret",
    AUTHSIGNAL_TENANT_ID: "test-tenant",
    AUTHSIGNAL_API_URL: `http://localhost:${MOCK_PORT}/v1`,
    AUTHSIGNAL_FLOW_ACTION_CODE: ACTION,
    PINGONE_ENVIRONMENT_ID: "test-env",
    PINGONE_CLIENT_ID: "x",
    PINGONE_CLIENT_SECRET: "x",
    OIDC_PROVIDER_CLIENT_ID: CLIENT_ID,
    OIDC_PROVIDER_CLIENT_SECRET: CLIENT_SECRET,
    OIDC_PROVIDER_REDIRECT_URIS: REDIRECT_URI,
    OIDC_PROVIDER_SIGNING_KEY_JWK: JSON.stringify(signingKey),
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let appLog = "";
app.stdout.on("data", (d) => (appLog += d));
app.stderr.on("data", (d) => (appLog += d));

async function waitForApp() {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`${BASE}/health`)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`app did not start:\n${appLog}`);
}

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(`ok   ${name}`);
  } catch (error) {
    results.push(`FAIL ${name}\n     ${error.message}`);
    process.exitCode = 1;
  }
}

function authorizeUrl(overrides = {}) {
  const url = new URL(`${BASE}/oidc-provider/authorize`);
  const params = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid",
    state: "ping-state-123",
    nonce: "ping-nonce-456",
    login_hint: "alice@example.com",
    ...overrides,
  };
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  return url;
}

/** Runs authorize → (mock outcome) → callback. Returns the final redirect to PingOne. */
async function runFlow({ outcome = "success", authorize = {}, sendCookie = true } = {}) {
  const r1 = await fetch(authorizeUrl(authorize), { redirect: "manual" });
  assert.equal(r1.status, 302, `authorize status ${r1.status}`);
  const challengeUrl = new URL(r1.headers.get("location"));
  assert.equal(challengeUrl.host, "mfa.example.test");
  const cookie = r1.headers.get("set-cookie")?.split(";")[0];
  const token = challengeUrl.searchParams.get("challenge_token");
  flows.get(token).outcome = outcome;
  const back = new URL(challengeUrl.searchParams.get("redirect_url"));
  back.searchParams.set("challenge_token", token);
  const r2 = await fetch(back, { redirect: "manual", headers: sendCookie && cookie ? { cookie } : {} });
  return { r2, back, cookie };
}

function tokenRequest(body, auth = true) {
  return fetch(`${BASE}/oidc-provider/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(auth ? { Authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}` } : {}),
    },
    body: new URLSearchParams(body),
  });
}

try {
  await waitForApp();

  await test("discovery document is standard and self-consistent", async () => {
    const doc = await (await fetch(`${BASE}/.well-known/openid-configuration`)).json();
    assert.equal(doc.issuer, BASE);
    assert.deepEqual(doc.response_types_supported, ["code"]);
    assert.ok(doc.userinfo_endpoint && doc.jwks_uri && doc.token_endpoint && doc.authorization_endpoint);
    assert.deepEqual(doc.id_token_signing_alg_values_supported, ["RS256"]);
  });

  await test("happy path: code flow with PKCE returns a verifiable ID token", async () => {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const { r2 } = await runFlow({
      authorize: { code_challenge: challenge, code_challenge_method: "S256", acr_values: "mfa-required other" },
    });
    assert.equal(r2.status, 302);
    const dest = new URL(r2.headers.get("location"));
    assert.equal(dest.origin + dest.pathname, REDIRECT_URI);
    assert.equal(dest.searchParams.get("state"), "ping-state-123");
    const code = dest.searchParams.get("code");
    assert.ok(code);
    assert.deepEqual(lastStart.user, { userId: "alice@example.com" });
    assert.equal(lastStart.actionCode, ACTION);

    const tokenRes = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier });
    assert.equal(tokenRes.status, 200);
    assert.equal(tokenRes.headers.get("cache-control"), "no-store");
    const tokens = await tokenRes.json();
    const jwks = jose.createRemoteJWKSet(new URL(`${BASE}/oidc-provider/jwks`));
    const { payload } = await jose.jwtVerify(tokens.id_token, jwks, { issuer: BASE, audience: CLIENT_ID });
    assert.equal(payload.sub, "alice@example.com");
    assert.equal(payload.nonce, "ping-nonce-456");
    assert.equal(payload.acr, "mfa-required");
    assert.deepEqual(payload.amr, ["hwk", "user", "mfa"]);
    assert.deepEqual(payload.authsignal_verification_methods, ["PASSKEY"]);
    assert.ok(payload.iat && payload.exp && payload.auth_time);

    const userinfo = await fetch(`${BASE}/oidc-provider/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    assert.deepEqual(await userinfo.json(), { sub: "alice@example.com" });

    const replay = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier });
    assert.equal(replay.status, 400, "code must be single use");
  });

  await test("client_secret_post works; wrong secret and wrong redirect_uri are rejected", async () => {
    const { r2 } = await runFlow();
    const code = new URL(r2.headers.get("location")).searchParams.get("code");
    const bad = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, client_secret: "wrong" }, false);
    assert.equal(bad.status, 401);
    const mismatch = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: "https://evil.example/cb" });
    assert.equal(mismatch.status, 400);

    const { r2: again } = await runFlow();
    const code2 = new URL(again.headers.get("location")).searchParams.get("code");
    const ok = await tokenRequest({ grant_type: "authorization_code", code: code2, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }, false);
    assert.equal(ok.status, 200);
  });

  await test("PKCE: wrong code_verifier is rejected", async () => {
    const challenge = createHash("sha256").update("right").digest("base64url");
    const { r2 } = await runFlow({ authorize: { code_challenge: challenge, code_challenge_method: "S256" } });
    const code = new URL(r2.headers.get("location")).searchParams.get("code");
    const res = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: "wrong" });
    assert.equal(res.status, 400);
  });

  await test("failed flow returns access_denied to PingOne, no code", async () => {
    const { r2 } = await runFlow({ outcome: "failed" });
    const dest = new URL(r2.headers.get("location"));
    assert.equal(dest.searchParams.get("error"), "access_denied");
    assert.equal(dest.searchParams.get("state"), "ping-state-123");
    assert.equal(dest.searchParams.get("code"), null);
  });

  await test("flow that succeeds without any verification step is not reported as MFA", async () => {
    const { r2 } = await runFlow({ outcome: "nostep" });
    assert.equal(new URL(r2.headers.get("location")).searchParams.get("error"), "access_denied");
  });

  await test("callback without the browser-binding cookie gets an error, never a code", async () => {
    const { r2, back, cookie } = await runFlow({ sendCookie: false });
    assert.equal(r2.status, 302);
    const dest = new URL(r2.headers.get("location"));
    assert.equal(dest.searchParams.get("error"), "access_denied");
    assert.equal(dest.searchParams.get("code"), null);
    assert.equal(dest.searchParams.get("state"), "ping-state-123");
    // The browser that owns the transaction can still finish it.
    const owner = await fetch(back, { redirect: "manual", headers: { cookie } });
    assert.ok(new URL(owner.headers.get("location")).searchParams.get("code"));
  });

  await test("callback cannot be replayed", async () => {
    const { r2, back, cookie } = await runFlow();
    assert.equal(r2.status, 302);
    const replay = await fetch(back, { redirect: "manual", headers: { cookie } });
    assert.equal(replay.status, 400);
  });

  await test("authorize rejects unknown client and unregistered redirect_uri without redirecting", async () => {
    const a = await fetch(authorizeUrl({ client_id: "nope" }), { redirect: "manual" });
    assert.equal(a.status, 400);
    const b = await fetch(authorizeUrl({ redirect_uri: "https://evil.example/cb" }), { redirect: "manual" });
    assert.equal(b.status, 400);
    const c = await fetch(authorizeUrl({ redirect_uri: REDIRECT_URI + "/extra" }), { redirect: "manual" });
    assert.equal(c.status, 400);
  });

  await test("authorize without login_hint returns login_required", async () => {
    const r = await fetch(authorizeUrl({ login_hint: undefined }), { redirect: "manual" });
    const dest = new URL(r.headers.get("location"));
    assert.equal(dest.searchParams.get("error"), "login_required");
    assert.equal(dest.searchParams.get("state"), "ping-state-123");
  });

  await test("authorize rejects response_type=id_token and plain PKCE", async () => {
    const a = await fetch(authorizeUrl({ response_type: "id_token" }), { redirect: "manual" });
    assert.equal(new URL(a.headers.get("location")).searchParams.get("error"), "unsupported_response_type");
    const b = await fetch(authorizeUrl({ code_challenge: "abc", code_challenge_method: "plain" }), { redirect: "manual" });
    assert.equal(new URL(b.headers.get("location")).searchParams.get("error"), "invalid_request");
  });

  await test("login_hint accepts plus-alias emails and rejects unsafe characters", async () => {
    const { r2 } = await runFlow({ authorize: { login_hint: "alice+ping@example.com" } });
    assert.ok(new URL(r2.headers.get("location")).searchParams.get("code"));
    assert.deepEqual(lastStart.user, { userId: "alice+ping@example.com" });
    const bad = await fetch(authorizeUrl({ login_hint: "{{local.x.payload.output.username}}" }), { redirect: "manual" });
    assert.equal(new URL(bad.headers.get("location")).searchParams.get("error"), "invalid_request");
  });

  await test("userinfo rejects unknown tokens", async () => {
    const r = await fetch(`${BASE}/oidc-provider/userinfo`, { headers: { Authorization: "Bearer nope" } });
    assert.equal(r.status, 401);
  });
} finally {
  app.kill();
  mock.close();
  console.log(results.join("\n"));
  if (process.exitCode) console.log("\n--- app log ---\n" + appLog);
}
