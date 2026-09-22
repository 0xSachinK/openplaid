/** Interpretation of supplied evidence, never authentication of its origin. */
export type PaymentObservation = {
  schemaVersion: "1";
  provider: string;
  transactionId: string;
  payer: { id: string; scheme: "mercury-party-id"; provenance: "transaction.primaryPartyId" };
  payee: {
    id: string;
    scheme: "us-routing-account";
    provenance: "transaction.details.domesticWireRoutingInfo";
  };
  amountMinor: string;
  currency: "USD";
  direction: "outgoing";
  status: "sent";
  timestamp: string;
  timestampMeaning: "postedAt";
  sourceAuthenticated: false;
  limitations: string[];
};
export type Interpretation =
  | { outcome: "supported"; payment: PaymentObservation }
  | { outcome: "insufficient_evidence" | "unsupported"; reason: string };
export type PaymentClaim = {
  payerId: string;
  payeeId: string;
  amountMinor: string;
  currency: string;
};
