// wallet-guard — standalone server (thin wrapper over lib/screen.js).
// Screens a transaction / approval BEFORE signing and returns a verdict.
// Dependency-free Node.js (built-in http + fetch only). No keys, no secrets.
//
// Run:  node server.mjs            (PORT env var, default 3000)
//       PORT=3000 node server.mjs
//
// Endpoints:
//   GET  /health  -> {"status":"ok","agent":"wallet-guard","version":"0.1.0"}
//   GET  /        -> agent card (JSON)
//   POST /screen  -> {chainId, from, to, value, data}  (BSC chainId 56 only)

import http from "node:http";
import { screen, isAddress, parseValue, VERSION } from "./lib/screen.js";

const RPC_TIMEOUT_MS = 8000;

// --- HTTP server ---
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", "http://localhost");

    if (req.method === "GET" && url.pathname === "/health") {
      return sendJson(res, 200, { status: "ok", agent: "wallet-guard", version: VERSION });
    }

    if (req.method === "GET" && url.pathname === "/") {
      return sendJson(res, 200, {
        name: "wallet-guard",
        description: "Screens a BSC transaction or approval before signing and returns a verdict (safe / caution / danger).",
        version: VERSION,
        chain: "BSC (chainId 56) only",
        example: 'curl -s -X POST http://localhost:3000/screen -H "content-type: application/json" -d \'{"chainId":"56","from":"0xE5942c0FA3f5f309670B721ca795eaD565B3C55a","to":"0x55d398326f99059fF775485246999027B3197955","value":"0","data":"0x095ea7b3"}\'',
      });
    }

    if (req.method === "POST" && url.pathname === "/screen") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
        if (raw.length > 1_000_000) req.destroy();
      });
      req.on("end", async () => {
        let body;
        try {
          body = JSON.parse(raw);
        } catch {
          return sendJson(res, 400, { error: "invalid JSON body" });
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return sendJson(res, 400, { error: "body must be a JSON object" });
        }
        // chainId: BSC only
        const chainId = body.chainId;
        if (chainId === undefined || chainId === null || String(chainId) !== "56") {
          return sendJson(res, 400, { error: "only BSC chainId 56 is supported" });
        }
        if (!isAddress(body.from)) {
          return sendJson(res, 400, { error: "from must be a 42-character 0x address" });
        }
        if (!isAddress(body.to)) {
          return sendJson(res, 400, { error: "to must be a 42-character 0x address" });
        }
        if (body.value !== undefined && body.value !== null && parseValue(body.value) === null) {
          return sendJson(res, 400, { error: "value must be a decimal or 0x hex string" });
        }
        if (body.data !== undefined && body.data !== null) {
          if (typeof body.data !== "string" || !/^0x([0-9a-fA-F]*)$/.test(body.data) || body.data.length % 2 !== 0) {
            return sendJson(res, 400, { error: "data must be a 0x hex string with even length" });
          }
        }
        try {
          const result = await screen(body, { rpcTimeoutMs: RPC_TIMEOUT_MS });
          console.log(`${req.method} ${url.pathname} verdict=${result.verdict} risk=${result.risk_score}`);
          return sendJson(res, 200, result);
        } catch (e) {
          console.log(`${req.method} ${url.pathname} verdict=error ${String(e?.message || e)}`);
          return sendJson(res, 500, { error: "screening failed", detail: String(e?.message || e) });
        }
      });
      return;
    }

    return sendJson(res, 404, { error: "not found" });
  } catch (e) {
    return sendJson(res, 500, { error: "internal error", detail: String(e?.message || e) });
  }
});

const PORT = Number(process.env.PORT || 3000);
server.listen(PORT, "0.0.0.0", () => {
  console.log(`wallet-guard v${VERSION} listening on 0.0.0.0:${PORT}`);
});
