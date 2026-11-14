// Runs a localtunnel for the guard server and writes the public URL to a file.
// Usage: node tunnel.mjs [port] [subdomain] [outfile]
import localtunnel from "localtunnel";
import fs from "node:fs";

const port = Number(process.argv[2] || 3000);
const subdomain = process.argv[3] || "hendryzu-guard";
const outFile = process.argv[4] || "/tmp/guard-url.txt";

const tunnel = await localtunnel({ port, subdomain });
fs.writeFileSync(outFile, tunnel.url + "\n");
console.log("tunnel url:", tunnel.url);
tunnel.on("close", () => {
  console.log("tunnel closed");
  process.exit(1);
});
tunnel.on("error", (e) => {
  console.log("tunnel error:", e?.message || e);
});
// keep alive
setInterval(() => {}, 60_000);
