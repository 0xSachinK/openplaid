"""Minimal signed verification receipts, never payment authorizations.

The runtime must sign only after its evidence pipeline completes. This module does
not expose a signing endpoint. The same RSA key bound into Nitro attestation signs
receipts with a domain-separated PSS signature; encryption uses OAEP separately.
"""
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .attestation import verify_document
from .common import Rejected, b64, canonical, fields, hex_digest, identifier, require, unb64

DOMAIN = b"OpenPlaid verification receipt v1\x00"
CLAIMS = ("audience", "attempt", "ticket", "bindingDigest", "capability", "result", "issuedAt", "expiresAt")
RESULTS = ("verified", "contradicted", "needs_review", "blocked")


def validate(claims, now=None):
    now = time.time() if now is None else now
    fields(claims, CLAIMS)
    require(claims["audience"] == "openplaid-contribution-verification-v1", "receipt_audience")
    for name in ("attempt", "ticket", "capability"):
        identifier(claims[name])
    hex_digest(claims["bindingDigest"])
    require(claims["result"] in RESULTS, "invalid_result")
    require(type(claims["issuedAt"]) is int and type(claims["expiresAt"]) is int and
            now - 300 <= claims["issuedAt"] <= now + 5 and
            now < claims["expiresAt"] <= claims["issuedAt"] + 300, "receipt_expired")


def sign(claims, enclave_key):
    validate(claims)
    require(isinstance(enclave_key, rsa.RSAPrivateKey) and enclave_key.key_size == 3072,
            "invalid_receipt_key")
    signature = enclave_key.sign(DOMAIN + canonical(claims),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    return {"claims": dict(claims), "signature": b64(signature)}


def verify(receipt, *, attestation, nonce, public_key_der, release):
    # release and nonce are independently pinned controller inputs.
    require(release.get("liveVerification") is True, "live_verification_unavailable")
    verify_document(attestation, nonce=nonce, public_key_der=public_key_der, release=release)
    fields(receipt, ("claims", "signature"))
    validate(receipt["claims"])
    try:
        key = serialization.load_der_public_key(public_key_der)
        require(isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072, "invalid_receipt_key")
        key.verify(unb64(receipt["signature"], 384), DOMAIN + canonical(receipt["claims"]),
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    except Exception as error:
        raise Rejected("invalid_receipt_signature") from error
    return dict(receipt["claims"])
