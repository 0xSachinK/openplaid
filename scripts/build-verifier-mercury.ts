import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { transformSync } from "esbuild";

const sha = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");
const toolchain = JSON.parse(readFileSync("verification/infra/javy.json", "utf8"));
const pin = toolchain.binaries[`${process.platform}-${process.arch}`];
const compiler = resolve(process.env.JAVY_BIN ?? ".local/verification/javy");
if (!pin || sha(readFileSync(compiler)) !== pin.binarySha256) {
  throw new Error("Javy binary does not match the reviewed platform pin");
}
const source = readFileSync("banks/us/mercury/transformer.js", "utf8");
if (Buffer.byteLength(source) > 65536) throw new Error("Adapter source exceeds build limit");
const bundle = transformSync(source, {
  minify: true,
  format: "iife",
  globalName: "OpenPlaidMercury",
}).code;
const wrapper = readFileSync("verification/infra/mercury-wasm-entry.js", "utf8");
const directory = ".local/verification";
mkdirSync(directory, { recursive: true });
const javascript = `${directory}/mercury-wasm.js`;
const wasm = `${directory}/mercury.wasm`;
writeFileSync(javascript, `${bundle}\n${wrapper}`);
const compile = () => {
  const result = spawnSync(
    compiler,
    ["build", javascript, "-C", "deterministic=y", "-C", "dynamic=n", "-o", wasm],
    {
      env: {},
      timeout: 10000,
      maxBuffer: 65536,
      stdio: "pipe",
    },
  );
  if (result.error || result.status !== 0) throw new Error("Bounded adapter compilation failed");
  const artifact = readFileSync(wasm);
  if (artifact.length > 2 * 1024 * 1024) throw new Error("Wasm artifact exceeds sandbox limit");
  return artifact;
};
const artifact = compile();
if (sha(compile()) !== sha(artifact)) throw new Error("Adapter build is not deterministic");
const manifest = {
  schemaVersion: "1",
  sourceSha256: sha(source),
  wrapperSha256: sha(wrapper),
  compiledJavaScriptSha256: sha(readFileSync(javascript)),
  compilerSha256: pin.binarySha256,
  artifactSha256: sha(artifact),
  artifactBytes: artifact.length,
  capability: "us/mercury/outgoing-domestic-usd-wire-sent",
  repeatBuildMatched: true,
  admissionGranted: false,
};
writeFileSync(`${directory}/mercury-wasm-build.json`, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify(manifest));
