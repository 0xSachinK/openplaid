import type { Interpretation, PaymentClaim } from "./types";
/** Exact identifiers only. Memos and display names never establish payer/payee identity. */
export function matchPayment(observation: Interpretation, claim: PaymentClaim) {
  if (observation.outcome !== "supported") return observation;
  const p = observation.payment;
  if (!/^[1-9]\d*$/.test(claim.amountMinor) || !claim.payerId || !claim.payeeId)
    return {
      outcome: "insufficient_evidence",
      reason: "Claim needs exact identities and positive minor units",
    } as const;
  const matches =
    p.payer.id === claim.payerId &&
    p.payee.id === claim.payeeId &&
    p.amountMinor === claim.amountMinor &&
    p.currency === claim.currency;
  return { outcome: matches ? "supported" : "contradicted", payment: p } as const;
}
