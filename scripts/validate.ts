import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const files = execFileSync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { encoding: "utf8" },
)
  .split("\0")
  .filter(Boolean);
let reports = 0;
let fixtures = 0;
let banks = 0;
const fail = (file: string, message: string): never => {
  throw new Error(`${file}: ${message}`);
};
for (const file of files.filter((f) =>
  /^banks\/[^/]+\/[^/]+\/(manifest\.json|reports\/.*\.json|fixtures\/.*\.json)$/.test(f),
)) {
  const data = JSON.parse(readFileSync(file, "utf8"));
  const bank = file.split("/").slice(0, 3).join("/");
  if (file.endsWith("/manifest.json")) {
    for (const key of [
      "schemaVersion",
      "id",
      "name",
      "country",
      "status",
      "version",
      "surface",
      "capability",
    ])
      if (typeof data[key] !== "string" || !data[key]) fail(file, `Missing ${key}`);
    if (data.id !== bank.slice(6) || data.schemaVersion !== "1" || data.status !== "experimental")
      fail(file, "Invalid manifest identity/version/status");
    if (
      !Array.isArray(data.maintainers) ||
      !data.maintainers.length ||
      !Array.isArray(data.unsupported)
    )
      fail(file, "Document maintainers and limitations");
    banks++;
  } else if (file.includes("/fixtures/")) {
    if (
      !["synthetic", "sanitized"].includes(data.provenance) ||
      typeof data.description !== "string" ||
      !data.input ||
      !data.expected
    )
      fail(
        file,
        "Fixture needs provenance, description, input and independently reviewed expected output",
      );
    fixtures++;
  } else {
    const allowed = [
      "schemaVersion",
      "provider",
      "adapterRevision",
      "harnessRevision",
      "testedAt",
      "reporter",
      "surface",
      "capability",
      "outcome",
      "evidenceClass",
      "fixtureRefs",
      "limitations",
      "summary",
    ];
    if (Object.keys(data).some((k) => !allowed.includes(k))) fail(file, "Unexpected report fields");
    for (const key of allowed.filter((k) => !["fixtureRefs", "limitations"].includes(k)))
      if (typeof data[key] !== "string" || !data[key]) fail(file, `Missing ${key}`);
    if (data.schemaVersion !== "1" || data.provider !== bank.slice(6))
      fail(file, "Wrong schema or provider");
    if (!/^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(data.reporter))
      fail(file, "Use a public GitHub handle");
    if (
      !["pass", "fail", "partial", "blocked", "not-tested"].includes(data.outcome) ||
      !["contributor-live", "fixture-only", "reviewer-live"].includes(data.evidenceClass)
    )
      fail(file, "Invalid report classification");
    if (
      !/^\d{4}-\d{2}-\d{2}T.*Z$/.test(data.testedAt) ||
      !Number.isFinite(Date.parse(data.testedAt)) ||
      Date.parse(data.testedAt) > Date.now() + 300000
    )
      fail(file, "Invalid test date");
    for (const key of ["adapterRevision", "harnessRevision"]) {
      if (!/^[a-f\d]{40}$/.test(data[key])) fail(file, `Use a full commit SHA for ${key}`);
      try {
        execFileSync("git", ["cat-file", "-e", `${data[key]}^{commit}`], { stdio: "ignore" });
      } catch {
        fail(file, `${key} is not a repository commit`);
      }
    }
    if (
      !Array.isArray(data.limitations) ||
      !data.limitations.length ||
      !data.limitations.every((x: unknown) => typeof x === "string")
    )
      fail(file, "Explicit limitations required");
    if (!Array.isArray(data.fixtureRefs)) fail(file, "fixtureRefs must be an array");
    for (const ref of data.fixtureRefs) {
      if (
        typeof ref !== "string" ||
        !/^fixtures\/[a-zA-Z0-9._-]+\.json$/.test(ref) ||
        !existsSync(resolve(bank, ref))
      )
        fail(file, "Invalid fixture reference");
    }
    reports++;
  }
}
if (!banks || !fixtures) throw new Error("At least one bank and fixture required");
console.log(`Validated ${banks} providers, ${fixtures} fixtures and ${reports} versioned reports.`);
