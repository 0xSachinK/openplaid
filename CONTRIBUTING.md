# Contributing

Read [privacy rules](docs/privacy.md) first. Start with [the contribution skill](skills/contribute-bank/SKILL.md) or the [testing skill](skills/test-bank/SKILL.md).

1. Open a bank request or pick an issue. State bank, country, surface and payment type. An unfunded issue is not a promise of payment.
2. Inspect your own authorized bank session locally. Prefer the smallest read-only response containing the required facts. Do not assume a browser-capable agent has network capture access.
3. Create `banks/<country>/<bank>/` with README, manifest, pure transformer, tests and fixtures. Follow Mercury's folder conventions, but do not copy Mercury-specific semantics to another bank.
4. Define who A and B mean, identity provenance, amount units, currency, status, timestamp, transaction-ID scope and unsupported cases. If the evidence cannot support the claim, say so.
5. Add synthetic or carefully sanitized fixtures with expected outputs justified independently of the implementation. Preserve relationships while replacing identifying values.
6. Run `npm run check`. Inspect every staged file, including binary files and Git history; run `npm run privacy -- --staged` before pushing.
7. Open a PR using the checklist. An integration can merge as experimental after review and tests; no ten-person prerequisite. Reviews assess semantics, not just green CI.
8. Live reports go in the provider's `reports/` directory, targeting an existing full commit SHA. Use [report format](docs/evidence.md). Do not upload full transcripts. New reports do not inherit compatibility across revisions.

By contributing you represent that you have the right to submit the code/data under the project's MIT license. Do not submit employer-owned or proprietary implementation without the necessary rights. No copyright assignment is requested.

Maintainer: @0xSachinK. Report broken integrations with the failure issue template; maintainers label stale or broken scopes and link corrective PRs. No bank or payer authenticity guarantee is attached to merge status.
