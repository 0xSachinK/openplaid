import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Filesystem discovery also works on deployment builders without Git metadata.
const files = readdirSync("banks", { recursive: true, withFileTypes: true })
  .filter((entry) => entry.isFile())
  .map((entry) => join(entry.parentPath, entry.name).replaceAll("\\", "/"));
const providers = files
  .filter((f) => /^banks\/[^/]+\/[^/]+\/manifest.json$/.test(f))
  .map((file) => {
    const bank = file.replace("/manifest.json", "");
    const manifest = JSON.parse(readFileSync(file, "utf8"));
    const reports = files
      .filter((f) => f.startsWith(`${bank}/reports/`) && f.endsWith(".json"))
      .map((f) => JSON.parse(readFileSync(f, "utf8")));
    // Separate compatibility scopes and revisions. No carry-forward and no person/account uniqueness claim.
    const scopes = new Map<string, Map<string, (typeof reports)[number]>>();
    for (const r of reports) {
      const key = `${r.adapterRevision}:${r.harnessRevision}:${r.surface}:${r.capability}`;
      const reporters = scopes.get(key) ?? new Map();
      const old = reporters.get(r.reporter.toLowerCase());
      if (!old || r.testedAt > old.testedAt) reporters.set(r.reporter.toLowerCase(), r);
      scopes.set(key, reporters);
    }
    const evidence = [...scopes.entries()].map(([scope, reporters]) => ({
      scope,
      reports: [...reporters.values()].map(({ reporter, outcome, evidenceClass, testedAt }) => ({
        reporter,
        outcome,
        evidenceClass,
        testedAt,
      })),
      distinctReportingHandles: reporters.size,
    }));
    return {
      ...manifest,
      reportCount: reports.length,
      evidence,
      source: `https://github.com/0xSachinK/openplaid/tree/main/${bank}`,
    };
  });
writeFileSync(
  "app/public/catalog.json",
  `${JSON.stringify({ schemaVersion: "1", providers }, null, 2)}\n`,
);
console.log(`Built catalog for ${providers.length} providers.`);
