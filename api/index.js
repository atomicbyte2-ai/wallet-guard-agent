// wallet-guard — Vercel serverless function (thin wrapper over ../lib/screen.js).
//
// Same contract as the standalone server: GET -> health, POST /screen -> verdict.
// (On the live hendryzu deployment the function is served at the project
// root, so GET / is the health card and POST /screen is the screen call;
// the /api/* paths 404 there — use the root routes.)
//
// Vercel Hobby functions are capped at 10 s, so this handler runs each
// check with a 5 s per-call timeout AND an overall 9 s deadline from
// request start: worst case is two sequential RPC calls (eth_getCode,
// then getPair) at 5 s + 4 s = 9 s, plus response overhead — safely
// inside the limit. If the deadline is hit, the affected check reports
// "unknown" (fail-open) and the verdict is computed from the rest.

import { screen, isAddress, parseValue, VERSION } from "../lib/screen.js";

const RPC_TIMEOUT_MS = 5000;
const TOTAL_DEADLINE_MS = 9000;

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  res.end(body);
}

export default async function handler(req, res) {
  try {
    if (req.method === "GET") {
      return sendJson(res, 200, {
        status: "ok",
        agent: "wallet-guard",
        version: VERSION,
        description: "Screens a BSC transaction or approval before signing and returns a verdict (safe / caution / danger).",
        chain: "BSC (chainId 56) only",
        usage: "POST /api/index with {chainId:'56', from:'0x...', to:'0x...', value:'0', data:'0x...'}",
      });
    }

    if (req.method !== "POST") {
      return sendJson(res, 404, { error: "not found" });
    }

    // Vercel pre-parses JSON bodies into req.body; accept a raw string too.
    let body = req.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch {
        return sendJson(res, 400, { error: "invalid JSON body" });
      }
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
      const result = await screen(body, {
        rpcTimeoutMs: RPC_TIMEOUT_MS,
        deadlineMs: Date.now() + TOTAL_DEADLINE_MS,
      });
      return sendJson(res, 200, result);
    } catch (e) {
      return sendJson(res, 500, { error: "screening failed", detail: String(e?.message || e) });
    }
  } catch (e) {
    return sendJson(res, 500, { error: "internal error", detail: String(e?.message || e) });
  }
}
