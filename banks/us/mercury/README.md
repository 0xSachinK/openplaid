# Mercury — experimental

Scope: Mercury web **outgoing domestic USD wires**, using the transactions-lite response. Input is the response envelope with `data.transactions` and `data.parties`, plus an explicit transaction ID. The pure function `interpretMercury` is in transformer.js (checked by TypeScript). `matchPayment` compares its output against exact payer, payee, amount and currency claims.

## Semantics

- Payer: `primaryPartyId` must resolve uniquely to an `internalDepositoryAccountKind` party. This is a Mercury account reference, not a verified legal identity. Never use a display name or caller-supplied legal name to fill the gap.
- Payee: full routing number plus account number from domestic-wire routing information. Masked values are insufficient. The routing/account pair is an identifier, not a validation that an account exists.
- Amount: negative debit in major USD units; convert to positive minor units without rounding. Reject excessive precision and unsupported range. USD follows the domestic-wire surface; explicit conflicting currency fails.
- Status: only `sent`, with no active holds and the supported `notDisputable` field value. These observed values do not prove recipient credit or legal irreversibility.
- Time: UTC `postedAt`, not creation time or estimated delivery date.
- ID: the selected Mercury ledger transaction ID, not a cross-bank canonical payment ID. Memos are untrusted and do not establish uniqueness or identity.

ACH, cards, incoming/international wires, arbitrary status variants and recipient credit are unsupported. Missing or ambiguous facts return insufficient evidence. Selection is page-local: if the transaction is absent, navigate to the correct page. This does not claim to have searched complete history.

## Local acquisition

1. Sign into your own Mercury account in Chrome using normal login/MFA.
2. Open Transactions and find an existing outgoing domestic wire. Opening transaction details is read-only. Do not create or resend payments.
3. With your browser agent's authorized network-inspection capability or browser developer tools, inspect the response from the transaction-history request the UI itself makes. Preserve the matching `parties` entries with the selected row. Do not copy request cookies, CSRF headers or a full HAR into a fixture.
4. Run the pure parser locally against the response and selected ID. Compare every emitted fact with the transaction details. The code does not supply credentials or replay requests.
5. Publish only a synthetic/sanitized fixture and a revision-specific report, following the contribution skill. Do not upload the raw response to the landing page or a public issue.

The history request observed on 2026-09-23 is a read-only **POST** to
`backend.mercury.com/organizations/{organizationId}/transactions-lite`, not a GET.
Its body selects a bounded page and date ordering. This endpoint observation does
not authorize arbitrary POST replay or establish a reusable credential set. See the
[verifier source review](../../../docs/verification.md#mercury-history-operation-review--2026-09-23)
for the constrained implementation and remaining live-acquisition limitations.

## Validation

Synthetic baseline tests cover status, debit precision, identifiers, holds, timestamps, unsupported methods, duplicates and instruction-like memos. Live observations are separate in reports/; a synthetic fixture alone is not live validation. Any report must say whether it executed the parser or merely inspected the UI/schema.

For a browser agent with an in-memory JavaScript evaluation environment, `npm run bundle:mercury` generates `.local/mercury-parser.js` containing the exact compiled parser (no banking data). Evaluate that bundle locally, then call `OpenPlaidMercury.interpretMercury(response, transactionId)` on an authorized captured response. Only publish pass/fail summaries, never the returned real identities or financial values. The bundle does not fetch or upload anything. Preserve the source commit and bundle/source hashes privately for reproducibility. Posted timestamps preserve up to six fractional digits.
