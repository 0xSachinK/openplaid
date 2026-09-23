# OpenPlaid

**Banking integrations, built together.**

An MIT-licensed library of bank adapters, payment semantics, privacy-safe fixtures, and community test reports. Bring your bank account and your coding agent. Turn what works for you into knowledge anyone can inspect, reproduce, and maintain.

[Website](https://openplaid.com) · [Contribute](CONTRIBUTING.md) · [Integrations](https://openplaid.com/#providers) · [Incentives](docs/incentives.md)

**[Round 1: 60 integration bounties across 41 geographies](https://github.com/0xSachinK/openplaid/issues/64)** — $10,000 planned, $150–$200 per integration, **funding pending**. Contributions from every geography are welcome; the paid shortlist is not an eligibility boundary.

## Start with your agent

Give your browser-capable coding agent this prompt:

> Read AGENTS.md and skills/contribute-bank/SKILL.md in https://github.com/0xSachinK/openplaid. Help me contribute my bank's payment integration. Keep raw captures and credentials local. Start by identifying the bank, supported transaction type and evidence needed to determine whether A paid B. Do not initiate payments.

No extension is required. Your agent needs its own authorized browser tooling; this repository does not provide remote bank access. You sign into your own bank normally.

## Run locally

Node 20.19+ and npm. No secrets or bank account required for fixture tests.

```sh
git clone https://github.com/0xSachinK/openplaid.git
cd openplaid
npm ci --ignore-scripts
npm run check
npm run dev
```

`app/` contains the landing page. `banks/<country>/<bank>/` contains an adapter, manifest, tests, fixtures and reports. `lib/` defines a small shared observation format, not a published SDK.

## What a result means

A parser can tell you what supplied evidence says. It cannot establish that the evidence came from a bank. `supported` means the supported interpretation is present, not that funds should be released. Downstream attestation systems must authenticate evidence and apply their own settlement policy. No signing service, TEE deployment, payment initiation or on-chain verifier is included.

Community reports are revision-specific claims, not certified unique people or bank accounts. Failures and partial results are useful. Ten reporting handles is a community milestone, not a trust or payout threshold. [Evidence model](docs/evidence.md).

## Contribute

- Add a bank adapter with meaningful negative tests.
- Reproduce a provider against your own account and submit a privacy-safe report.
- Add an edge case, fix a broken integration or improve acquisition instructions.
- Sponsor a reviewed issue. Round 1 bounties are **funding pending**; no reward is promised until a sponsor explicitly funds an issue.

[Contribution guide](CONTRIBUTING.md) · [Privacy rules](docs/privacy.md) · [Security](SECURITY.md)

OpenPlaid is an independent community project. It is not affiliated with, endorsed by, or sponsored by Plaid Inc. or named financial institutions. Bank names identify integrations only.

Copyright (c) 2026 Sachin Kumar and OpenPlaid contributors. [MIT](LICENSE).
