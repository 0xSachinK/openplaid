import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { transformSync } from "esbuild";

const source = readFileSync("banks/us/mercury/transformer.js", "utf8");
const bundle = transformSync(source, {
  minify: true,
  format: "iife",
  globalName: "OpenPlaidMercury",
}).code;
mkdirSync(".local", { recursive: true });
writeFileSync(".local/mercury-parser.js", bundle);
console.log(`Parser bundle: .local/mercury-parser.js (no banking data)`);
console.log(`Source SHA-256: ${createHash("sha256").update(source).digest("hex")}`);
console.log(`Bundle SHA-256: ${createHash("sha256").update(bundle).digest("hex")}`);
