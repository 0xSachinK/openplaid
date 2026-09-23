# OpenPlaid

**Banking integrations, built together.**

An MIT-licensed library of bank adapters, payment semantics, privacy-safe fixtures, and community test reports. Bring your bank account and your coding agent. Turn what works for you into knowledge anyone can inspect, reproduce, and maintain.

[Website](https://openplaid.com) · [Contribute](CONTRIBUTING.md) · [Integrations](https://openplaid.com/#providers) · [Incentives](docs/incentives.md)

**[Round 1: 60 integration bounties across 41 geographies](https://github.com/0xSachinK/openplaid/issues/64)** — $150–$200 per integration. Check each issue for its current funding status and terms. Contributions from every geography are welcome; the bounty shortlist is not an eligibility boundary.

## Start with your agent

Give your browser-capable coding agent this prompt:

> Read AGENTS.md and skills/contribute-bank/SKILL.md in https://github.com/0xSachinK/openplaid. Help me contribute my bank's payment integration. Keep raw captures and credentials local. Start by identifying the bank, supported transaction type and evidence needed to determine whether A paid B. Do not initiate payments.

No extension is required. Your agent needs its own authorized browser tooling; this repository does not provide remote bank access. You sign into your own bank normally.

## Run locally

Node 20.19+, npm, Python 3.11+ and OpenSSL. No secrets or bank account required for fixture tests.

```sh
git clone https://github.com/0xSachinK/openplaid.git
cd openplaid
npm ci --ignore-scripts
npm run verify:setup
npm run check
npm run dev
```

`app/` contains the landing page. `banks/<country>/<bank>/` contains an adapter, manifest, tests, fixtures and reports. `lib/` defines a small shared observation format, not a published SDK.

## What a result means

A parser can tell you what supplied evidence says. It cannot establish that the evidence came from a bank. `supported` means the supported interpretation is present, not that funds should be released. Downstream attestation systems must authenticate evidence and apply their own settlement policy. The verification service is under development; its release manifest currently refuses live secret sharing. No production settlement or automatic payout is enabled.

Community reports are revision-specific claims, not certified unique people or bank accounts. Failures and partial results are useful. Ten reporting handles is a community milestone, not a trust or payout threshold. [Evidence model](docs/evidence.md).

## Agent maintenance and verification

OpenPlaid is designed for agent-assisted maintenance. Public prompts, explicit policies and machine-readable decisions make reviews inspectable. A private verifier is being built to authenticate bank evidence inside an AWS enclave, with bounded AI review and explicit account-owner consent.

**Current status: development, not a live verification service.** No scheduled agent tasks or automatic payouts are enabled. Existing bounty terms remain unchanged.

September 23, 2026 validation:

- [Nitro hardware tests](verification/infra/evidence/2026-09-23-nitro-components.json) passed attestation/tampering checks, 16 component tests and four synthetic Mercury Wasm cases.
- [Independent CI builds](verification/infra/evidence/2026-09-23-independent-builds.json) match PCR0/1/2 on two separate runners. Whole EIF files still differ; a reproducible signed release and hardware validation of that release remain unfinished.
- A [synthetic Venice probe](verification/infra/evidence/2026-09-23-venice-synthetic-protocol.json) reached encrypted inference, but response signature byte binding failed. No bank data was sent.
- The consent handshake and acquisition/oracle/adapter stages have synthetic integration tests. Live bank acquisition, verified model dispatch, runtime receipts and hardware end-to-end testing remain release gates.

Run `npm run verify:readiness` for a machine-readable report. It currently exits with status 2 because live verification is unavailable. Passing parser tests or merging a contribution does not enable it.

[Verification guide](docs/verification.md) · [Agent contract](verification/agent-contract.json) · [Operator skill](skills/operate-verifier/SKILL.md) · [Release status](verification/release.json)

## Contribute

- Add a bank adapter with meaningful negative tests.
- Reproduce a provider against your own account and submit a privacy-safe report.
- Add an edge case, fix a broken integration or improve acquisition instructions.
- Sponsor a reviewed issue. No reward is promised until a sponsor explicitly funds an issue.

[Contribution guide](CONTRIBUTING.md) · [Privacy rules](docs/privacy.md) · [Security](SECURITY.md)

OpenPlaid is an independent community project. It is not affiliated with, endorsed by, or sponsored by Plaid Inc. or named financial institutions. Bank names identify integrations only.

Copyright (c) 2026 Sachin Kumar and OpenPlaid contributors. [MIT](LICENSE).
