"""Independent reference interpretation of the documented Mercury fixture surface.

This does not authenticate input. Only an approved acquisition path can establish
provenance. Kept separate from contributor JavaScript; no dynamic adapter imports.
The narrow claim is sender-reported sent USD wire, not recipient credit/finality.
"""
import datetime
import decimal
import math
import re

from .common import require
from .evaluation import ROLES

CAPABILITY = "us/mercury/outgoing-domestic-usd-wire-sent"


def object_value(value):
    require(isinstance(value, dict), "oracle_missing_evidence")
    return value


def text(value):
    require(isinstance(value, str) and 0 < len(value) <= 256 and value.strip(),
            "oracle_missing_evidence")
    return value


def reference_facts(document, selected_transaction):
    """Return scoped facts or a fixed rejection code, never infer absent identities."""
    selected_transaction = text(selected_transaction)
    data = object_value(object_value(document).get("data"))
    transactions, parties = data.get("transactions"), data.get("parties")
    require(isinstance(transactions, list) and isinstance(parties, list) and
            len(transactions) <= 1000 and len(parties) <= 1000, "oracle_invalid_collection")
    # Reject malformed collection members rather than silently dropping evidence.
    require(all(isinstance(row, dict) for row in transactions + parties), "oracle_invalid_collection")
    matches = [row for row in transactions if row.get("id") == selected_transaction]
    require(len(matches) == 1, "oracle_ambiguous_transaction")
    row = matches[0]
    details = object_value(row.get("details"))
    require(details.get("kind") == "outgoingDomesticWire", "oracle_unsupported_payment")
    require(row.get("status") == "sent" and row.get("activeHolds") == [] and
            row.get("disputed") == "notDisputable", "oracle_unsupported_status")
    require("currency" not in row or row["currency"] == "USD", "oracle_currency_conflict")
    amount = row.get("amount")
    require(type(amount) in (int, float) and
            (type(amount) is not int or amount.bit_length() <= 64) and
            math.isfinite(amount) and amount < 0,
            "oracle_invalid_amount")
    # Decimal arithmetic, independent of the contributor's JS integer conversion.
    amount_text = str(-amount)
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?", amount_text),
            "oracle_invalid_amount")
    minor = decimal.Decimal(amount_text) * 100
    require(0 < minor <= 9007199254740991 and minor == minor.to_integral_value(),
            "oracle_invalid_amount")
    timestamp = text(row.get("postedAt"))
    require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", timestamp),
            "oracle_invalid_time")
    try:
        datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        require(False, "oracle_invalid_time")
    payer = text(row.get("primaryPartyId"))
    payer_rows = [party for party in parties if party.get("id") == payer]
    require(len(payer_rows) == 1 and payer_rows[0].get("kind") == "internalDepositoryAccountKind",
            "oracle_ambiguous_payer")
    routing = object_value(details.get("domesticWireRoutingInfo"))
    routing_number, account_number = routing.get("routingNumber"), routing.get("accountNumber")
    require(isinstance(routing_number, str) and re.fullmatch(r"[0-9]{9}", routing_number) and
            isinstance(account_number, str) and re.fullmatch(r"[0-9]{4,17}", account_number),
            "oracle_missing_payee")
    return {"payer": payer, "payee": routing_number + ":" + account_number,
            "amount": str(int(minor)), "currency": "USD", "status": "sent",
            "transaction": selected_transaction, "direction": "outgoing", "timestamp": timestamp,
            "timestampMeaning": "postedAt", "capability": CAPABILITY}


def evidence_candidates(document, selected_transaction):
    """Produce field references from the reference extraction, not adapter claims.

    No memos, display names or arbitrary transaction text is forwarded. Returning
    these private values does not authorize transmitting them to an AI provider.
    """
    facts = reference_facts(document, selected_transaction)
    candidates = {role: {role + "-0": {"value": facts[role], "transaction": facts["transaction"]}}
                  for role in ROLES}
    return facts, candidates
