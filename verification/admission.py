"""Controller-signed permission to allocate one challenge, never to decrypt or spend."""
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .common import Rejected, b64, canonical, fields, hex_digest, identifier, require, unb64

CLAIMS = ("audience", "attempt", "bindingDigest", "policyDigest", "enclaveKeyDigest", "expiresAt")


def validate(claims):
    fields(claims, CLAIMS)
    require(claims["audience"] == "openplaid-challenge-v1", "admission_audience")
    identifier(claims["attempt"])
    for name in ("bindingDigest", "policyDigest", "enclaveKeyDigest"):
        hex_digest(claims[name])
    now = time.time()
    require(type(claims["expiresAt"]) is int and now < claims["expiresAt"] <= now + 120,
            "admission_expired")


def issue(claims, private_key):
    validate(claims)
    return {"claims": dict(claims), "signature": b64(private_key.sign(canonical(claims)))}


def verify(grant, public_key, *, enclave_key_digest, policy_digest):
    fields(grant, ("claims", "signature"))
    claims = grant["claims"]
    validate(claims)
    require(claims["enclaveKeyDigest"] == enclave_key_digest and
            claims["policyDigest"] == policy_digest, "admission_binding")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            unb64(grant["signature"], 64), canonical(claims))
    except Exception as error:
        raise Rejected("invalid_admission_signature") from error
    return dict(claims)
