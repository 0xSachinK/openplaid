/**
 * Pure, read-only Mercury transaction interpretation. No login, network or signing.
 * @param {unknown} input A Mercury web transactions-lite response.
 * @param {string} transactionId Selected Mercury ledger transaction ID.
 * @returns {import('../../../lib/types.js').Interpretation}
 */
export function interpretMercury(input, transactionId) {
  const fail = (/** @type {string} */ reason) =>
    /** @type {const} */ ({ outcome: "insufficient_evidence", reason });
  const object = (/** @type {unknown} */ v) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? /** @type {Record<string, unknown>} */ (v)
      : null;
  const nonempty = (/** @type {unknown} */ v) => typeof v === "string" && v.trim().length > 0;
  const root = object(input);
  const data = object(root?.data);
  if (!data || !Array.isArray(data.transactions) || !Array.isArray(data.parties))
    return fail("Expected transactions and parties arrays");
  if (!nonempty(transactionId)) return fail("A transaction ID is required");
  const rows = data.transactions.filter((row) => object(row)?.id === transactionId);
  if (rows.length !== 1) return fail("Selected transaction must occur exactly once in this page");
  const row = object(rows[0]);
  if (!row) return fail("Invalid transaction");
  const details = object(row.details);
  if (details?.kind !== "outgoingDomesticWire")
    return { outcome: "unsupported", reason: "Only outgoing domestic USD wires are supported" };
  if (row.status !== "sent") return fail("Transaction is not bank-reported sent");
  if (!Array.isArray(row.activeHolds) || row.activeHolds.length !== 0)
    return fail("Active holds must be present and empty");
  if (row.disputed !== "notDisputable") return fail("Dispute state is not supported");
  if (typeof row.amount !== "number" || !Number.isFinite(row.amount) || row.amount >= 0)
    return fail("Expected a finite negative USD debit");
  // Decimal-string conversion avoids floating-point multiplication and rounding.
  const decimal = String(-row.amount);
  if (!/^(0|[1-9]\d*)(\.\d{1,2})?$/.test(decimal))
    return fail("Amount must have at most two decimals");
  const [whole, fraction = ""] = decimal.split(".");
  const cents = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, "0"));
  if (cents <= 0n || cents > BigInt(Number.MAX_SAFE_INTEGER))
    return fail("Amount outside supported range");
  if (row.currency !== undefined && row.currency !== "USD") return fail("Conflicting currency");
  if (
    typeof row.postedAt !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(row.postedAt)
  )
    return fail("Expected a UTC postedAt timestamp");
  const date = new Date(row.postedAt);
  if (
    !Number.isFinite(date.getTime()) ||
    date.toISOString().slice(0, 19) !== row.postedAt.slice(0, 19)
  )
    return fail("Invalid postedAt timestamp");
  const routing = object(details.domesticWireRoutingInfo);
  if (
    !routing ||
    typeof routing.routingNumber !== "string" ||
    !/^\d{9}$/.test(routing.routingNumber) ||
    typeof routing.accountNumber !== "string" ||
    !/^\d{4,17}$/.test(routing.accountNumber)
  )
    return fail("Full recipient routing and account identifiers are required");
  if (!nonempty(row.primaryPartyId)) return fail("Payer account identifier is missing");
  const parties = data.parties.filter((p) => object(p)?.id === row.primaryPartyId);
  if (parties.length !== 1 || object(parties[0])?.kind !== "internalDepositoryAccountKind")
    return fail("Payer must resolve to exactly one internal depository account");
  return {
    outcome: "supported",
    payment: {
      schemaVersion: "1",
      provider: "us/mercury",
      transactionId,
      payer: {
        id: /** @type {string} */ (row.primaryPartyId),
        scheme: "mercury-party-id",
        provenance: "transaction.primaryPartyId",
      },
      payee: {
        id: `${routing.routingNumber}:${routing.accountNumber}`,
        scheme: "us-routing-account",
        provenance: "transaction.details.domesticWireRoutingInfo",
      },
      amountMinor: cents.toString(),
      currency: "USD",
      direction: "outgoing",
      status: "sent",
      timestamp: row.postedAt,
      timestampMeaning: "postedAt",
      sourceAuthenticated: false,
      limitations: [
        "Input authenticity is not established by this parser.",
        "Sent is the sender-bank status, not proof of recipient credit or irreversible settlement.",
        "Payer identity is a Mercury account reference, not a verified legal person.",
        "Transaction ID is local to this ledger; no cross-bank deduplication is claimed.",
        "USD is inferred from the supported domestic-wire surface.",
      ],
    },
  };
}
