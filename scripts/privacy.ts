import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const staged = process.argv.includes("--staged");
const files = execFileSync(
  "git",
  staged
    ? ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"]
    : ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { encoding: "utf8" },
)
  .split("\0")
  .filter(Boolean);
const findings: string[] = [];
for (const file of files) {
  if (/(^|\/)(\.env[^/]*|\.local)(\/|$)|\.(har|pem|key)$/i.test(file)) {
    findings.push(`${file}: raw capture/credential file`);
    continue;
  }
  const content = staged
    ? execFileSync("git", ["show", `:${file}`], { encoding: "utf8", maxBuffer: 5000000 })
    : readFileSync(file, "utf8");
  // Never echo matching contents: a failed check must not become a second leak.
  const rules: [string, RegExp][] = [
    ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
    ["GitHub token", /\b(?:gh[pousr]_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,})\b/],
    ["credential header", /"(?:cookie|authorization|x-csrf-protect|set-cookie)"\s*:\s*"[^"\n]+"/i],
    ["JWT", /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/],
  ];
  for (const [name, rule] of rules)
    if (rule.test(content)) findings.push(`${file}: possible ${name}`);
  if (file.includes("/fixtures/") && file.endsWith(".json")) {
    const d = JSON.parse(content);
    if (!["synthetic", "sanitized"].includes(d.provenance))
      findings.push(`${file}: missing fixture provenance`);
    if (/https?:\/\/[^\s"]+[?&](?:token|key|session|code)=/i.test(content))
      findings.push(`${file}: credential-bearing URL`);
  }
}
if (findings.length) {
  console.error(findings.join("\n"));
  process.exitCode = 1;
} else
  console.log(
    `Privacy heuristics passed for ${files.length} files. Human pre-publication review is still required.`,
  );
