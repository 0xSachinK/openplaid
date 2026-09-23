"""AWS Nitro COSE verification. No server-provided 'verified' boolean is trusted."""
import io
import subprocess
import tempfile
import time
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .common import Rejected, digest, hex_digest, require

ROOT = Path(__file__).parent / "trust/aws-nitro-root.pem"
ROOT_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"


def decode_one(raw):
    stream = io.BytesIO(raw)
    value = cbor2.CBORDecoder(stream).decode()
    require(stream.read() == b"", "trailing_cbor")
    return value


def verify_document(raw, *, nonce, public_key_der, release, now=None):
    """release must come from the caller's independently trusted/pinned artifact.

    Returns sanitized metadata. All optional signed fields are verified before consent.
    """
    now = time.time() if now is None else now
    require(isinstance(raw, bytes) and len(raw) <= 32768, "attestation_size")
    require(isinstance(nonce, bytes) and len(nonce) == 32, "nonce_size")
    require(release.get("status") == "approved" and release.get("expiresAt", 0) > now,
            "release_not_approved")
    require(isinstance(public_key_der, bytes) and len(public_key_der) <= 4096, "invalid_public_key")
    expected = release.get("measurements", {})
    require(set(expected) == {"0", "1", "2", "8"}, "missing_measurements")
    for measurement in expected.values():
        require(isinstance(measurement, str) and len(measurement) == 96 and
                all(c in "0123456789abcdef" for c in measurement) and
                measurement != "0" * 96, "invalid_measurement")
    hex_digest(release.get("policyDigest"))
    try:
        cose = decode_one(raw)
        if isinstance(cose, cbor2.CBORTag):
            require(cose.tag == 18, "invalid_cose_tag")
            cose = cose.value
        require(isinstance(cose, (list, tuple)) and len(cose) == 4, "invalid_cose")
        protected, unprotected, payload, signature = cose
        require(isinstance(protected, bytes) and isinstance(payload, bytes) and
                isinstance(signature, bytes) and len(signature) == 96, "invalid_cose")
        require(decode_one(protected) == {1: -35} and unprotected == {}, "invalid_algorithm")
        doc = decode_one(payload)
        require(isinstance(doc, dict) and doc.get("digest") == "SHA384", "invalid_document")
        require(type(doc.get("timestamp")) is int and
                now * 1000 - 60000 <= doc["timestamp"] <= now * 1000 + 5000, "stale_attestation")
        require(doc.get("nonce") == nonce, "nonce_mismatch")
        require(doc.get("public_key") == public_key_der, "key_binding_mismatch")
        require(doc.get("user_data") == bytes.fromhex(release["policyDigest"]), "policy_mismatch")
        pcrs = doc.get("pcrs")
        require(isinstance(pcrs, dict), "missing_measurements")
        for index, value in expected.items():
            require(pcrs.get(int(index)) == bytes.fromhex(value), "measurement_mismatch")
        root = x509.load_pem_x509_certificate(ROOT.read_bytes())
        require(root.fingerprint(hashes.SHA256()).hex() == ROOT_SHA256, "root_mismatch")
        leaf = x509.load_der_x509_certificate(doc["certificate"])
        require(isinstance(doc["cabundle"], list) and 1 <= len(doc["cabundle"]) <= 8,
                "invalid_chain")
        chain = b"".join(x509.load_der_x509_certificate(cert).public_bytes(serialization.Encoding.PEM)
                         for cert in doc["cabundle"])
        # OpenSSL handles validity, CA constraints, signatures, path lengths and unknown critical
        # extensions. Explicit trust anchor only; no network or system CA store is consulted.
        with tempfile.TemporaryDirectory(prefix="openplaid-cert-") as directory:
            path = Path(directory)
            (path / "leaf").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
            (path / "chain").write_bytes(chain)
            checked = subprocess.run(
                ["openssl", "verify", "-trusted", str(ROOT), "-untrusted", str(path / "chain"),
                 "-purpose", "any", "-attime", str(int(now)), str(path / "leaf")],
                capture_output=True, timeout=5, check=False)
            require(checked.returncode == 0, "invalid_certificate_chain")
        key = leaf.public_key()
        require(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP384R1),
                "invalid_signing_key")
        sig_der = encode_dss_signature(int.from_bytes(signature[:48], "big"),
                                      int.from_bytes(signature[48:], "big"))
        structure = cbor2.dumps(["Signature1", protected, b"", payload])
        key.verify(sig_der, structure, ec.ECDSA(hashes.SHA384()))
        return {"verified": True, "releaseDigest": digest(release),
                "policyDigest": release["policyDigest"], "measurements": expected}
    except Rejected:
        raise
    except Exception as error:
        raise Rejected("invalid_attestation") from error


def policy_digest(policy, prompt, source_policy, model_policy, operator_policy):
    # Every authority/evidence destination is part of the consent commitment.
    return digest({"service": policy, "prompt": prompt, "source": source_policy,
                   "model": model_policy, "operator": operator_policy})
