"""Short-lived, signed execution capabilities for a single measured enclave key.

The trusted controller signs only after atomic reservation. Contributors and models
never receive the signing key. These permits authorize verification, not payments.
"""
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .common import Rejected, b64, canonical, fields, hex_digest, identifier, require, unb64

PERMIT_FIELDS = ("audience", "attempt", "ticket", "artifactDigest", "policyDigest",
                 "enclaveKeyDigest", "challenge", "expiresAt", "maximumMicroUsd")


def validate(claims, *, now=None):
    now = time.time() if now is None else now
    fields(claims, PERMIT_FIELDS)
    require(claims["audience"] == "openplaid-verification-v1", "permit_audience")
    for name in ("attempt", "ticket"):
        identifier(claims[name])
    for name in ("artifactDigest", "policyDigest", "enclaveKeyDigest", "challenge"):
        hex_digest(claims[name])
    require(type(claims["expiresAt"]) is int and now < claims["expiresAt"] <= now + 120,
            "permit_expired")
    require(type(claims["maximumMicroUsd"]) is int and 0 < claims["maximumMicroUsd"] <= 50000,
            "permit_budget")


def issue(claims, private_key):
    validate(claims)
    return {"claims": dict(claims), "signature": b64(private_key.sign(canonical(claims)))}


def verify(permit, public_key, *, enclave_key_digest, policy_digest, artifact_digest, challenge):
    fields(permit, ("claims", "signature"))
    claims = permit["claims"]
    validate(claims)
    require(claims["enclaveKeyDigest"] == enclave_key_digest and
            claims["policyDigest"] == policy_digest and
            claims["artifactDigest"] == artifact_digest and
            claims["challenge"] == challenge, "permit_binding")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(unb64(permit["signature"], 64), canonical(claims))
    except Exception as error:
        raise Rejected("invalid_permit_signature") from error
    return dict(claims)
