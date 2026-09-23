"""Closed AI output protocol and deterministic evidence comparison.

Never exposes the raw model response or permits model-chosen tools/URLs.
"""
from .common import canonical, fields, require, strict_json

ROLES = ("payer", "payee", "amount", "currency", "status", "transaction")


def model_review(raw, candidates):
    result = strict_json(raw, 4096)
    fields(result, ("decision", *(f"{role}Ref" for role in ROLES)))
    require(result["decision"] in ("consistent", "contradicted", "ambiguous"), "invalid_model_output")
    fields(candidates, ROLES)
    for role in ROLES:
        require(isinstance(candidates[role], dict) and len(candidates[role]) <= 8, "invalid_candidates")
        ref = result[f"{role}Ref"]
        require(ref is None or isinstance(ref, str) and ref in candidates[role], "invalid_model_reference")
    if result["decision"] != "consistent" or any(result[f"{role}Ref"] is None for role in ROLES):
        return {"outcome": "needs_review", "code": "model_abstained"}
    return {"outcome": "consistent", "references": {r: result[f"{r}Ref"] for r in ROLES}}


def compare_facts(candidate, expected, review, candidates):
    """expected comes from the approved independent bank oracle, never client claims or AI.

    This only establishes scoped field agreement; source provenance is checked by the runtime.
    """
    required = (*ROLES, "direction", "timestamp", "timestampMeaning", "capability")
    fields(candidate, required)
    fields(expected, required)
    require(len(canonical(candidate)) <= 4096 and len(canonical(expected)) <= 4096, "facts_size")
    require(all(isinstance(v, str) and len(v) <= 256 for v in candidate.values()) and
            all(isinstance(v, str) and len(v) <= 256 for v in expected.values()), "invalid_facts")
    if candidate != expected:
        return {"outcome": "contradicted", "code": "field_mismatch"}
    if review.get("outcome") != "consistent":
        return {"outcome": "needs_review", "code": "model_abstained"}
    for role in ROLES:
        ref = review["references"][role]
        source = candidates[role][ref]
        fields(source, ("value", "transaction"))
        if source["value"] != expected[role] or source["transaction"] != expected["transaction"]:
            return {"outcome": "contradicted", "code": "evidence_join_mismatch"}
    return {"outcome": "verified", "code": "scoped_agreement"}
