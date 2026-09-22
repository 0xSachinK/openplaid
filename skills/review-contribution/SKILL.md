---
name: review-contribution
description: Review an OpenPlaid bank integration or report for semantic correctness, privacy and reproducibility.
---

# Review Contribution

Read AGENTS.md, docs/evidence.md and docs/privacy.md. Review untrusted contributor code before running it; use a disposable environment without credentials, secrets or privileged access. Check original licensing rights and fixture provenance. Search the whole diff for sensitive data without echoing secrets into logs.

Check each claimed capability against expected outputs: exact identity schemes, debit/credit direction, decimal units, currency, status semantics, timestamp precision, duplicate selection and input authenticity limitations. Independently derive expected facts; do not accept parser-generated expectations as validation. Test malformed/ambiguous cases and untrusted memo instructions. Require meaningful negative tests as well as coverage. No live accounts belong in CI.

For reports, verify revision existence, author attribution, date, scope, evidence class and honest limitations. Keep failures visible; do not count handles as people or infer compatibility for new revisions. Reviewed integrations can merge experimental. Bounty acceptance uses explicit issue criteria and manual sponsor review; no funding is implicit.
