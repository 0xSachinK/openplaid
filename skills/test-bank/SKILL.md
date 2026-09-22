---
name: test-bank
description: Reproduce a bank adapter on an authorized local session and submit a revision-specific community report.
---

# Test Bank

Read AGENTS.md, docs/privacy.md, docs/evidence.md and the provider README. Record the exact adapter and harness commit before testing. Sign-in and browser inspection stay in the contributor's environment. Run fixture tests, then the actual parser on minimum live evidence if authorized and possible. Compare identity, amount, currency, status and time against the bank's UI. Do not mistake UI inspection or a sanitized fixture replay for execution on original live evidence.

Report pass, fail, partial, blocked or not-tested accurately. Separate acquisition failures from parser failures. Publish only a structured report and privacy-safe reproducer, never a raw transcript, screenshot or banking record. Include unsupported cases and scope limits. Use a public GitHub handle, not claims of verified unique users. An agent's signed response does not authenticate its input. Run all repository checks and the staged privacy check before pushing.
