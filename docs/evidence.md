# Evidence and community reports

Fixture tests establish behavior on known inputs. Live reports are contributor claims. Neither authenticates a bank response, proves a unique human, or certifies settlement. Signed model inference would not prove the truth of its browser inputs.

A report records exactly what was tested. Create it after the tested implementation commit exists (avoids self-referential commit hashes):

```json
{
  "schemaVersion": "1",
  "provider": "us/mercury",
  "adapterRevision": "FULL_40_CHARACTER_COMMIT_SHA",
  "harnessRevision": "FULL_40_CHARACTER_COMMIT_SHA",
  "testedAt": "2026-09-23T00:00:00Z",
  "reporter": "YOUR_GITHUB_HANDLE",
  "surface": "web-transactions-lite",
  "capability": "outgoing-domestic-usd-wire",
  "outcome": "partial",
  "evidenceClass": "contributor-live",
  "fixtureRefs": ["fixtures/sent.synthetic.json"],
  "limitations": ["One account; no independent source attestation"],
  "summary": "State what ran and what remains untested, without banking data."
}
```

Allowed outcomes: pass, fail, partial, blocked, not-tested. Evidence classes: fixture-only, contributor-live, reviewer-live. Fixture-only reports never count as live reproductions. A maintainer checks that the PR author is the reporting handle or explains attribution; JSON alone cannot prove authorship.

`npm run catalog` groups reports by adapter revision, harness revision, surface and capability. Within each scope it shows each public handle's latest outcome, preserving all original reports. No automatic carry-forward between versions. A ten-handle milestone is not ten independent people and does not trigger rewards. Read dates, failures and limitations, not just counts. Counts are submitted reports, not measured population success rates.

Payer and payee identifiers need explicit schemes/provenance. A display name or memo is not a verified identity. A sender's `sent` status is not recipient credit. Cross-bank duplicate prevention and irreversible settlement require separate evidence and policy.
