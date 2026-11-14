// wallet-guard — pure screening logic (no HTTP, no Node http dependency).
//
// screen({ chainId, from, to, value, data }, options) returns
//   { verdict: "safe"|"caution"|"danger", risk_score, reasons[], checks[] }
//
// options:
//   rpcTimeoutMs — per-RPC-call timeout (default 8000)
//   deadlineMs   — absolute epoch-ms deadline; each RPC call is capped at
//                  min(rpcTimeoutMs, deadlineMs - now) so the whole screen
//                  never runs past the deadline (used by the Vercel path,
//                  where the function must answer in < 10 s).
//
// Five checks, all live via eth_call to the BSC RPC. A failed RPC marks
// that check "unknown" — fail-open, never crash. Behavior is identical
// to the original server.mjs; this file is the single source of truth.

export const VERSION = "0.1.0";
export const RPC_URL = "https://bsc-dataseed.binance.org";
export const DEFAULT_RPC_TIMEOUT_MS = 8000;

// --- hardcoded constants (public, on-chain) ---
export const WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c";
export const PANCAKE_V2_FACTORY = "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73";
// CONFIRMED scam token: Mars Nexus XU — no liquidity, unsellable.
// Attack pattern: victim connects an agent wallet via a Mars Nexus QR login,
// the bot sweeps nearly all BNB and force-swaps it into XU.
export const DENYLIST = new Set([
  "0x62be29443c0f5aaaa13aaaa2c363b8b3b0957335", // Mars Nexus XU
]);
const DENYLIST_REASONS = {
  "0x62be29443c0f5aaaa13aaaa2c363b8b3b0957335":
    "known scam token (Mars Nexus XU)",
};

const APPROVE_SEL = "0x095ea7b3"; // approve(address,uint256)
const SET_APPROVAL_FOR_ALL_SEL = "0xa22cb465"; // setApprovalForAll(address,bool)
const GET_PAIR_SEL = "0xe6a43905"; // getPair(address,address)
const UINT256_MAX = (1n << 256n) - 1n;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

// --- helpers ---
export function isAddress(v) {
  return typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
}

export function parseValue(v) {
  // Accept "0", "123", "0x..." — return BigInt or null on bad input.
  if (v === undefined || v === null || v === "") return 0n;
  if (typeof v !== "string") return null;
  try {
    if (v.startsWith("0x") || v.startsWith("0X")) return BigInt(v);
    if (/^\d+$/.test(v)) return BigInt(v);
    return null;
  } catch {
    return null;
  }
}

function formatBnb(wei) {
  // wei (BigInt) -> "0.5" style BNB string, no float precision loss.
  const whole = wei / 10n ** 18n;
  const frac = wei % 10n ** 18n;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(18, "0").replace(/0+$/, "").slice(0, 6);
  return `${whole}.${fracStr}`;
}

function pad32(hexNoPrefix) {
  return hexNoPrefix.toLowerCase().padStart(64, "0");
}

function addrToWord(addr) {
  return pad32(addr.slice(2));
}

function wordToAddress(word) {
  // 32-byte word (hex, no 0x) -> last 20 bytes as address.
  return "0x" + word.slice(-40);
}

// --- RPC (timeout-aware) ---
function effectiveTimeout(rpcTimeoutMs, deadlineMs) {
  if (deadlineMs == null) return rpcTimeoutMs;
  const remaining = deadlineMs - Date.now();
  if (remaining <= 0) return 0;
  return Math.min(rpcTimeoutMs, remaining);
}

async function rpc(method, params, rpcTimeoutMs, deadlineMs) {
  const timeoutMs = effectiveTimeout(rpcTimeoutMs, deadlineMs);
  if (timeoutMs <= 0) return { ok: false, error: "deadline exceeded" };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ctrl.signal,
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const j = await res.json();
    if (j.error) return { ok: false, error: j.error.message || "rpc error" };
    return { ok: true, result: j.result };
  } catch (e) {
    return { ok: false, error: e.name === "AbortError" ? "timeout" : String(e.message || e) };
  } finally {
    clearTimeout(timer);
  }
}

async function ethGetCode(address, rpcTimeoutMs, deadlineMs) {
  return rpc("eth_getCode", [address, "latest"], rpcTimeoutMs, deadlineMs);
}

async function ethCall(to, data, rpcTimeoutMs, deadlineMs) {
  return rpc("eth_call", [{ to, data }, "latest"], rpcTimeoutMs, deadlineMs);
}

async function hasV2Pair(token, other, rpcTimeoutMs, deadlineMs) {
  const data = GET_PAIR_SEL + addrToWord(token) + addrToWord(other);
  const r = await ethCall(PANCAKE_V2_FACTORY, data, rpcTimeoutMs, deadlineMs);
  if (!r.ok || typeof r.result !== "string") return { ok: false, error: r.error || "bad result" };
  const pair = wordToAddress(r.result.slice(2));
  return { ok: true, pair: pair.toLowerCase() === ZERO_ADDRESS ? null : pair };
}

// --- screening ---
export async function screen(body, options = {}) {
  const rpcTimeoutMs = options.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
  const deadlineMs = options.deadlineMs ?? null;

  const checks = [];
  const reasons = [];
  let risk = 0;
  let danger = false;
  let caution = false;

  const { from, to, value, data } = body;
  const valueWei = parseValue(value ?? "0");
  const calldata = typeof data === "string" && data !== "" ? data : "0x";
  const hasData = calldata !== "0x" && calldata.length > 2;
  const selector = hasData ? calldata.slice(0, 10).toLowerCase() : null;

  // --- 1. target-kind ---
  const code = await ethGetCode(to, rpcTimeoutMs, deadlineMs);
  let isEoa = null;
  if (!code.ok) {
    checks.push({ name: "target-kind", result: "unknown", detail: `eth_getCode failed (${code.error})` });
  } else {
    isEoa = code.result === "0x" || code.result === "0x0";
    checks.push({
      name: "target-kind",
      result: isEoa ? (valueWei > 0n ? "flag" : "pass") : "pass",
      detail: isEoa
        ? "target is an EOA (no contract code)"
        : "target is a contract",
    });
  }
  if (isEoa === true && valueWei > 0n) {
    danger = true;
    risk = Math.max(risk, 95);
    reasons.push(`value ${formatBnb(valueWei)} BNB sent to an EOA (no contract code) — nothing on-chain protects this transfer`);
  }

  // --- 2. approval-scan ---
  let approval = null; // {kind, spender, unlimited}
  if (selector === APPROVE_SEL) {
    if (calldata.length >= 10 + 64 + 64) {
      const spender = wordToAddress(calldata.slice(10, 10 + 64));
      const amount = BigInt("0x" + calldata.slice(10 + 64, 10 + 128));
      const unlimited = amount === UINT256_MAX;
      approval = { kind: "approve", spender, unlimited };
      checks.push({
        name: "approval-scan",
        result: unlimited ? "flag" : "pass",
        detail: unlimited
          ? `ERC20 approve to ${spender} with UNLIMITED amount (type(uint256).max)`
          : `ERC20 approve to ${spender}, limited amount ${amount.toString()}`,
      });
      if (unlimited) {
        caution = true;
        risk = Math.max(risk, 70);
        reasons.push(`unlimited ERC20 approval to ${spender} — the spender could drain the full token balance`);
      }
    } else {
      checks.push({ name: "approval-scan", result: "unknown", detail: "approve calldata too short to decode" });
    }
  } else if (selector === SET_APPROVAL_FOR_ALL_SEL) {
    if (calldata.length >= 10 + 64 + 64) {
      const spender = wordToAddress(calldata.slice(10, 10 + 64));
      const approved = BigInt("0x" + calldata.slice(10 + 64, 10 + 128)) !== 0n;
      approval = { kind: "setApprovalForAll", spender, unlimited: approved };
      checks.push({
        name: "approval-scan",
        result: approved ? "flag" : "pass",
        detail: approved
          ? `setApprovalForAll to ${spender} with approved=true (all NFTs)`
          : `setApprovalForAll to ${spender} with approved=false (revoke)`,
      });
      if (approved) {
        caution = true;
        risk = Math.max(risk, 70);
        reasons.push(`setApprovalForAll(true) to ${spender} — the operator could move every NFT in the collection`);
      }
    } else {
      checks.push({ name: "approval-scan", result: "unknown", detail: "setApprovalForAll calldata too short to decode" });
    }
  } else {
    checks.push({ name: "approval-scan", result: "pass", detail: "no approval in calldata" });
  }

  // --- 3. denylist ---
  const toLower = to.toLowerCase();
  const spenderLower = approval ? approval.spender.toLowerCase() : null;
  const denyHit = DENYLIST.has(toLower) ? toLower : (spenderLower && DENYLIST.has(spenderLower) ? spenderLower : null);
  if (denyHit) {
    checks.push({ name: "denylist", result: "flag", detail: `${denyHit} is denylisted` });
    danger = true;
    risk = 100;
    reasons.push(`${DENYLIST_REASONS[denyHit] || "known scam token"} — do not sign`);
  } else {
    checks.push({ name: "denylist", result: "pass", detail: "target and spender are not on the denylist" });
  }

  // --- 4. liquidity-signal (only when the call approves a token) ---
  if (approval && approval.kind === "approve") {
    const pair = await hasV2Pair(to, WBNB, rpcTimeoutMs, deadlineMs);
    if (!pair.ok) {
      checks.push({ name: "liquidity-signal", result: "unknown", detail: `getPair lookup failed (${pair.error})` });
    } else if (pair.pair === null) {
      checks.push({ name: "liquidity-signal", result: "flag", detail: "token has no PancakeSwap V2 pair with WBNB" });
      caution = true;
      risk = Math.max(risk, 55);
      reasons.push("token has no detectable WBNB liquidity on PancakeSwap V2 — a token with no pool is a classic honeypot/rug signal");
    } else {
      checks.push({ name: "liquidity-signal", result: "pass", detail: `PancakeSwap V2 pair with WBNB exists (${pair.pair})` });
    }
  }

  // --- 5. value-check ---
  if (approval && valueWei > 0n) {
    checks.push({ name: "value-check", result: "flag", detail: `non-zero value (${formatBnb(valueWei)} BNB) attached to an approval call` });
    caution = true;
    risk = Math.max(risk, 60);
    reasons.push("non-zero BNB value attached to an approval call — approvals should carry 0 value");
  } else {
    checks.push({ name: "value-check", result: "pass", detail: "no value attached to an approval, or no approval present" });
  }

  // --- verdict ---
  let verdict;
  if (danger) {
    verdict = "danger";
    risk = Math.min(100, Math.max(85, risk));
  } else if (caution) {
    verdict = "caution";
    risk = Math.min(84, Math.max(40, risk));
  } else {
    verdict = "safe";
    risk = Math.min(39, risk);
  }
  if (reasons.length === 0) reasons.push("no risk signals detected");

  return { verdict, risk_score: risk, reasons, checks };
}
