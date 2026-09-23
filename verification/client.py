"""Inspect a Nitro pilot over local vsock; never sends secrets.

Use an independently pinned release manifest, not one fetched from the same host.
"""
import argparse
import json
import secrets
import socket
import time
from pathlib import Path

from .attestation import verify_document
from .channel import encrypt_session
from .common import Rejected, b64, fields, hex_digest, require, strict_json, unb64
from .runtime import receive, send


def verified_session(response, *, nonce, release, context, attempt, binding_digest, session, consent):
    """Only this high-level helper should be used by an eventual secret-sharing UI.

    Release, attempt and binding_digest are caller-pinned state, not values copied
    from an untrusted server response. Consent is requested after showing verified
    release/destination/scope to the owner. This performs fresh verification again.
    """
    require(consent is True, "consent_required")
    require(release.get("liveVerification") is True, "live_verification_unavailable")
    fields(response, ("attestation", "publicKey", "policyDigest"))
    public_key = unb64(response["publicKey"], 4096)
    verified = verify_document(unb64(response["attestation"], 32768), nonce=nonce,
                               public_key_der=public_key, release=release)
    require(response["policyDigest"] == verified["policyDigest"], "policy_mismatch")
    fields(context, ("protocol", "attempt", "bindingDigest", "nonce", "expiresAt"))
    hex_digest(binding_digest)
    hex_digest(context["nonce"])
    require(context["protocol"] == "openplaid-session-v1" and context["attempt"] == attempt and
            context["bindingDigest"] == binding_digest, "session_binding_mismatch")
    require(type(context["expiresAt"]) is int and
            time.time() < context["expiresAt"] <= time.time() + 120, "expired_challenge")
    return encrypt_session(public_key, context, session, consent=True)


def call(cid, request):
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as stream:
        stream.settimeout(10)
        stream.connect((cid, 5000))
        send(stream, request)
        return receive(stream, 65536)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cid", type=int, required=True)
    parser.add_argument("--release", required=True)
    args = parser.parse_args()
    release = strict_json(Path(args.release).read_bytes())
    nonce = secrets.token_bytes(32)
    response = call(args.cid, {"operation": "attest", "nonce": b64(nonce)})
    result = verify_document(unb64(response["attestation"]), nonce=nonce,
                             public_key_der=unb64(response["publicKey"]), release=release)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"error":"attestation_verification_failed"}')
        raise SystemExit(1)
