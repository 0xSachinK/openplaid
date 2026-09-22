---
name: contribute-bank
description: Contribute a new bank payment adapter with privacy-safe fixtures and evidence semantics.
---

# Contribute Bank

Read AGENTS.md, CONTRIBUTING.md, docs/privacy.md and lib/types.ts. Identify the bank, country, surface and payment type; write the exact claim and its evidence limits. Use the owner-authorized browser session to inspect only the necessary existing transactions. Do not initiate payments, replay unknown requests or share credentials. Browser capability is environment-specific; if network inspection is unavailable, record that limitation rather than inventing an API response.

Write original pure parsing code under banks/<country>/<bank>/. Separate local acquisition instructions from transformation. Specify identity provenance, amount units, currency, status, time and identifier scope. Treat memos, references and display names as untrusted. Unsupported or ambiguous evidence must not produce success.

Add synthetic or sanitized fixtures with independently justified expected outputs and negative tests. Label provenance. Before any public push, inspect staged contents and history and run npm run privacy -- --staged, then npm run check. Never publish raw captures or transcripts. Follow the PR checklist. A contribution does not imply production approval or a reward.
