# wallet-guard

A wallet security guard that screens a BSC transaction or approval **before**
you sign it, and returns a verdict: `safe`, `caution`, or `danger`.

Built for the **Agent Games Wildcard** track by **hendryzu**.

## Why this exists

Two real incidents behind this agent:

1. **Mars Nexus (confirmed scam, Nov 2026).** A free-mint page lured victims
   into connecting an agent wallet via a QR login. A bot then swept nearly
   all the BNB out of the wallet and force-swapped it into a worthless token,
   **XU (`0x62be29443c0f5aaaa13Aaaa2C363b8B3B0957335`)** — no liquidity,
   unsellable. The wallets of people who never connected were untouched.
   This agent hardcodes that token on a denylist: any transaction touching
   it is an instant `danger`.
2. **Unlimited approvals — the classic drain vector.** An ERC20 `approve`
   for `type(uint256).max`, or an NFT `setApprovalForAll(true)`, hands a
   spender the right to move the full balance at any later time. A single
   careless signature can empty a wallet weeks after the fact. This agent
   decodes approval calldata and flags unlimited approvals, approvals that
   carry BNB value (approvals should carry 0), and tokens with no
   PancakeSwap V2 pool against WBNB (a token with no pool is a classic
   honeypot / rug signal).

## How to run

Dependency-free Node.js (built-in `http` + `fetch` only, Node 24):

```bash
node server.mjs            # listens on 0.0.0.0:3000
PORT=8080 node server.mjs  # custom port
```

## Deploy to Vercel

No environment variables needed — the agent is dependency-free and calls
the public BSC RPC directly.

1. In the [Vercel dashboard](https://vercel.com/new), **Import Git
   Repository** → pick `atomicbyte2-ai/wallet-guard-agent` → **Deploy**.
   (Framework preset: Node. No build command, no env vars.)
2. The live deployment serves the agent at the project root —
   `GET https://<your-project>.vercel.app/` returns the agent card,
   `POST https://<your-project>.vercel.app/screen` with the `/screen`
   body returns the verdict. (Verified live 2026-11-15; the `/api/*`
   paths return 404 on this deployment, so use the root routes.)

Vercel Hobby functions are capped at 10 s, so the serverless handler
(`api/index.js`) runs each RPC check with a 5 s timeout under an overall
9 s deadline — worst case is two sequential RPC calls at 5 s + 4 s, well
inside the limit. `vercel.json` sets `maxDuration: 60` (the Pro value);
if a Hobby deploy rejects anything above 10, set it to `10` — the
5 s / 9 s design already fits either way. The standalone server
(`server.mjs`) keeps the original 8 s per-check timeout.

## Endpoint contract

### `GET /health`

```json
{"status":"ok","agent":"wallet-guard","version":"0.1.0"}
```

### `GET /`

A small JSON agent card (name, description, example `POST /screen` curl).

### `POST /screen`

Body (JSON, all strings; BSC `chainId` 56 only — other chains are rejected):

```json
{"chainId":"56","from":"0x...","to":"0x...","value":"0","data":"0x..."}
```

- `from`, `to` — 42-character `0x` addresses (validated, else HTTP 400).
- `value` — optional, decimal or `0x` hex wei (default `"0"`).
- `data` — optional, `0x` hex calldata (default `"0x"`).
- Bad input never crashes the server — it returns HTTP 400 with an error.

Checks (BSC, via JSON-RPC `eth_call` to `https://bsc-dataseed.binance.org`,
8 s timeout each; a failed RPC marks that check `unknown` — it never
crashes the verdict):

| Check | What it does |
|---|---|
| `target-kind` | `eth_getCode(to)` — EOA vs contract. Value > 0 to an EOA is high risk. |
| `approval-scan` | Decodes `approve` (`0x095ea7b3`) and `setApprovalForAll` (`0xa22cb465`). Flags unlimited amounts and `approved=true`. Reports the spender. |
| `denylist` | Flags the confirmed Mars Nexus XU token, as target or as spender. |
| `liquidity-signal` | For ERC20 approvals, checks for a PancakeSwap V2 pair with WBNB via factory `0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73`. No pair = no detectable WBNB liquidity. |
| `value-check` | Flags non-zero BNB value attached to an approval call. |

Verdict logic:

- `danger` — denylist hit, or value > 0 sent to an EOA. `risk_score` 85–100.
- `caution` — unlimited approval, no detectable liquidity, or value > 0 with
  approval data. `risk_score` 40–84.
- `safe` — no signals. `risk_score` 0–39.

Response:

```json
{
  "verdict": "caution",
  "risk_score": 70,
  "reasons": ["unlimited ERC20 approval to 0x... — the spender could drain the full token balance"],
  "checks": [
    {"name": "target-kind", "result": "pass", "detail": "target is a contract"},
    {"name": "approval-scan", "result": "flag", "detail": "ERC20 approve to 0x... with UNLIMITED amount (type(uint256).max)"},
    {"name": "denylist", "result": "pass", "detail": "target and spender are not on the denylist"},
    {"name": "liquidity-signal", "result": "pass", "detail": "PancakeSwap V2 pair with WBNB exists (0x...)"},
    {"name": "value-check", "result": "pass", "detail": "no value attached to an approval, or no approval present"}
  ]
}
```

## Examples

Safe — limited USDT approve to the PancakeSwap V2 router:

```bash
curl -s -X POST http://localhost:3000/screen -H "content-type: application/json" -d '{
  "chainId": "56",
  "from": "0xE5942c0FA3f5f309670B721ca795eaD565B3C55a",
  "to": "0x55d398326f99059fF775485246999027B3197955",
  "value": "0",
  "data": "0x095ea7b300000000000000000000000010ed43c718714eb63d5aa57b78b54704e256024e00000000000000000000000000000000000000000000000000000000000f4240"
}'
```

Caution — unlimited approve (amount = `type(uint256).max`):

```bash
curl -s -X POST http://localhost:3000/screen -H "content-type: application/json" -d '{
  "chainId": "56",
  "from": "0xE5942c0FA3f5f309670B721ca795eaD565B3C55a",
  "to": "0x55d398326f99059fF775485246999027B3197955",
  "value": "0",
  "data": "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}'
```

Danger — target is the denylisted Mars Nexus XU token:

```bash
curl -s -X POST http://localhost:3000/screen -H "content-type: application/json" -d '{
  "chainId": "56",
  "from": "0xE5942c0FA3f5f309670B721ca795eaD565B3C55a",
  "to": "0x62be29443c0f5aaaa13Aaaa2C363b8B3B0957335",
  "value": "0",
  "data": "0x"
}'
```

## Notes

- This agent screens; it never signs, sends, or approves anything itself.
  It is a read-only guard — the decision to sign always stays with the user.
- The denylist is intentionally small and evidence-based: only tokens tied
  to a confirmed incident are listed. A `danger` verdict means "do not
  sign"; a `caution` verdict means "understand what you are approving
  before you sign".
- If the BSC RPC is unreachable, affected checks report `unknown` and the
  verdict is computed from the checks that did run (fail-open, never crash).
