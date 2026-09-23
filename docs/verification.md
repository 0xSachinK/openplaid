# Verification and agent maintenance

OpenPlaid is building a verifier that checks real bank evidence while keeping session
secrets inside an independently verifiable enclave. Agents can inspect the code,
public prompts, policies and release measurements before asking an account owner
to consent. AI advice does not independently authorize acceptance or payment.

## Current status

The repository includes a development implementation of transactional admission,
bounded budgets, agent judgments, AWS attestation verification, encrypted one-use
sessions, approved-operation acquisition, and a closed AI evaluation protocol.
The release manifest is deliberately **unreleased**, the Mercury acquisition policy
is **disabled**, and there is **no public live verification endpoint yet**. No bank
secrets should be sent until the release and end-to-end checks are complete.

No scheduled agent task or automatic payout is enabled. Existing Round 1 terms remain
unchanged. A contribution can still earn its advertised parser award without meeting
new, unpublished cryptographic-verification requirements.

## Readable by people and agents

- [Agent contract](../verification/agent-contract.json): capabilities, states, decisions and reason codes.
- [Operator skill](../skills/operate-verifier/SKILL.md): how an agent reviews and records progression.
- [Release manifest](../verification/release.json): independent release pinning and readiness.
- [Public model prompt](../verification/prompts/payment-review-v1.txt): the exact review task.
- [Service policy](../verification/policies/service.json): spending, attempts, sizes and authority limits.
- [Mercury source policy](../verification/policies/mercury.json): exact approved surface; currently pending review.
- [Deployment runbook](../verification/infra/README.md): pilot target, validation and cleanup.

```mermaid
flowchart LR
  A[Contribution] --> B[Agent admission judgment]
  B --> C[Reserve bounded attempt]
  C --> D[Verify release and ask owner consent]
  D --> E[Enclave reads approved bank operation]
  E --> F[Exact code checks and private AI review]
  F --> G[Agent acceptance judgment]
```

## Run locally

Python 3.11+ and OpenSSL are required for verifier development. No live credentials
are needed for the security tests.

```sh
python3 -m venv .local/verifier-venv
.local/verifier-venv/bin/pip install -r verification/requirements.lock
.local/verifier-venv/bin/python -m unittest discover -s verification/tests -v
.local/verifier-venv/bin/python -m verification.cli status
.local/verifier-venv/bin/python -m verification.cli --help
```

The local CLI is an authenticated-operator boundary by deployment, not a public HTTP
API. Do not expose it to PR code, contributors, or an agent interpreting bank content.
SQLite must live on one durable controller; do not run independent database replicas
and assume quotas are global. Judgments bind the current state version and an evidence
digest. A future scheduler can call the same interface; none is configured now.

## Protecting secrets

PCR8 identifies the release signing certificate, not the exact image. Clients require
PCR0/1/2 as well, a fresh nonce, a public key inside the signed attestation, and a policy
digest. The AWS root certificate is pinned by its published SHA-256 fingerprint.
Certificate-chain checks use OpenSSL; COSE signatures are verified locally. A boolean
from the server is never accepted as attestation.

After verification and explicit owner consent, the client encrypts the scoped session
to the attested key. Each challenge expires after two minutes and can be consumed once.
Credentials and original records are not written to the ledger, public logs, CI or Git.
Approved source policy constructs the entire bank request. Contributors cannot supply
arbitrary URLs, redirect targets, HTTP methods, or credential destinations.

Private AI processing must use a separately verified Venice E2EE connection from the
enclave. No plaintext or non-TEE fallback is permitted. Before this is fully integrated
and tested, live AI evaluation remains unavailable. Hosted Jev is not assumed to have
equivalent confidential processing.

## Abuse and griefing controls

An assigned contribution needs an operator judgment before consuming bank/model resources.
Attempts are tied to artifact, release, policy and prompt digests. Atomic reservations
prevent concurrent overspend; retries retain the original reservation. Failed/uncertain
attempts consume their upper-bound allowance. Five attempts and $0.25 per ticket are
development defaults. The task cap is $50, with a separate $5 inference reservation cap.
Infrastructure and purchases must be reserved before they are incurred. These controls
do not replace actual provider caps and finite resource lifetimes.

The AI receives a fixed task and bounded candidates, no tools or credentials. Output
accepts only enumerated decisions and known field references. No model explanations or
arbitrary completion text are returned to contributors. Exact fields and transaction
joins remain code checks. Unknown evidence and disagreement require review, not retries
until a model happens to agree. Public production prompts are versioned; private
adversarial holdouts must be stored separately and never run on untrusted PR hosts.

## Limits

Passing tests is not proof of no vulnerabilities. This development verifier has not
been independently audited. Mercury's current parser describes sender-bank-reported
sent domestic USD wires, not recipient credit or irreversible settlement. An OpenPlaid
verification result is not a Peer settlement signature. Signing, merging and payout
authority must remain separate from untrusted adapter code and model output.

## Machine-readable readiness

Run `npm run verify:readiness`. Exit code 2 means the release cannot accept secrets;
its JSON lists the specific blockers. Configuration alone cannot turn the pilot into
a live service. The current runtime only provides status and attestation operations.
The client secret-sharing helper additionally requires an explicitly live release,
fresh cryptographic verification, the caller's expected contribution binding, and consent.

The policy commitment covers service limits, source destinations, the public prompt,
model trust and controller key configuration. Changing any of these requires a new
reviewed commitment. Dependency installation uses pinned wheel hashes. An independently
reproduced enclave image and actual hardware evidence are still release requirements.

## Remaining release work

| Component | Current state | Required before live release |
| --- | --- | --- |
| Agent admission and spending | Local transactional CLI, tested | Trusted controller deployment and recovery procedure |
| Nitro identity and session channel | Crypto tests and pilot runtime | Hardware test, independent rebuild, published image/measurements |
| Bank acquisition | Bounded reader; source policy disabled | Review exact bank operation and scope; bounded relay DNS/process watchdog |
| Independent expected result | Not integrated | Bank-specific oracle reviewed separately from contributor code |
| Contributor execution | Not integrated | Resource-limited isolation with no credentials, signing key or external network |
| Venice review | Encryption and output validation tested locally | CPU/GPU/application verification, key binding and real provider test |
| Verification receipt | Signing, attestation validation and transactional controller acceptance tested | Integrate issuance with the completed enclave evidence pipeline |
| Live consent flow | Client helper only | End-to-end owner consent, encrypted submission and receipt verification |
| Recurring agent judgment | Intentionally absent | Separate future authorization; existing CLI remains usable manually |
| Awards and payouts | Existing published terms | Separate bounded award authority; model output never releases funds |

A trusted maintainer must review changes to the verifier, source/model policies,
release measurements and CI separately from ordinary adapter contributions. PR code
runs only in credential-free CI. Private holdouts and live credentials must never be
made available through a PR workflow or `pull_request_target` checkout.

### Receipt acceptance boundary

The controller cannot mark an attempt verified from a plain result string. It checks
an RSA-PSS receipt against a fresh Nitro-attested key and an independently pinned live
release, then atomically matches its ticket, capability and full reserved binding.
Receipts use a contribution-verification audience, short expiry, fixed fields and no
bank account/payment details. The ledger retains minimal claims and cryptographic
provenance digests for operator auditing. Duplicate delivery is idempotent; conflicts,
pause and revocation fail closed. Ordinary operator reconciliation can record a failed
attempt, but cannot manufacture success. Runtime issuance is still disabled until the
bank/oracle/sandbox/model pipeline exists and passes end-to-end verification.
