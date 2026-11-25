// Stand-in for the Authsignal Flows API and hosted UI that approves every
// challenge straight away. Use it to exercise the PingOne / DaVinci wiring
// without a real tenant, an authenticator or a one-time code.
//
//   node test/mock-authsignal.mjs
//   AUTHSIGNAL_API_URL=http://localhost:4621/v1 npm run dev
//
// Never point a deployed server at this: it verifies nobody.
import { randomBytes } from "node:crypto";
import http from "node:http";

const PORT = Number(process.env.MOCK_AUTHSIGNAL_PORT ?? 4621);
const flows = new Map(); // challengeToken -> { userId, actionCode, redirectUrl, used }

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  let raw = "";
  req.on("data", (chunk) => (raw += chunk));
  req.on("end", () => {
    const send = (status, json) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(json));
    };
    let body = {};
    try {
      body = raw ? JSON.parse(raw) : {};
    } catch {
      return send(400, { error: "invalid json" });
    }

    // Flows API: start
    if (req.method === "POST" && url.pathname === "/v1/flows") {
      const token = randomBytes(16).toString("hex");
      flows.set(token, {
        userId: body.user?.userId,
        actionCode: body.actionCode,
        redirectUrl: body.redirectUrl,
        used: false,
      });
      console.log(`start   ${body.actionCode} for ${body.user?.userId}`);
      return send(200, {
        challengeId: token,
        challengeToken: token,
        challengeUrl: `http://localhost:${PORT}/challenge?token=${token}`,
        action: { state: "CHALLENGE_REQUIRED" },
      });
    }

    // Hosted UI: approve and go back, the way the real page does after a code is entered
    if (req.method === "GET" && url.pathname === "/challenge") {
      const token = url.searchParams.get("token");
      const flow = flows.get(token);
      if (!flow) return send(404, { error: "unknown challenge" });
      const back = new URL(flow.redirectUrl);
      back.searchParams.set("challenge_token", token);
      console.log(`approve ${flow.userId}`);
      res.writeHead(302, { Location: back.toString() });
      return res.end();
    }

    // Flows API: verify (single use)
    if (req.method === "POST" && url.pathname === "/v1/flows/verify") {
      const flow = flows.get(body.challengeToken);
      if (!flow || flow.used || flow.actionCode !== body.actionCode) return send(400, { error: "invalid" });
      flow.used = true;
      console.log(`verify  ${flow.userId}`);
      return send(200, {
        challengeId: body.challengeToken,
        user: { userId: flow.userId },
        action: {
          state: "CHALLENGE_SUCCEEDED",
          completedSteps: [{ stepType: "VERIFICATION", verificationMethod: "EMAIL_OTP" }],
        },
      });
    }

    send(404, { error: "not found" });
  });
});

server.listen(PORT, () => console.log(`Mock Authsignal on http://localhost:${PORT} (approves every challenge)`));
