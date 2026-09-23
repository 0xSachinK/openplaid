"""One-use, context-bound hybrid encryption after attestation and explicit consent."""
import hashlib
import secrets
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import Rejected, b64, canonical, fields, require, strict_json, unb64


def encrypt_session(public_key_der, context, session, *, consent):
    require(consent is True, "consent_required")
    require(len(canonical(session)) <= 16384, "session_size")
    key = serialization.load_der_public_key(public_key_der)
    require(isinstance(key, rsa.RSAPublicKey) and key.key_size >= 3072, "invalid_public_key")
    secret = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    aad = canonical(context)
    wrapped = key.encrypt(secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                             algorithm=hashes.SHA256(), label=hashlib.sha256(aad).digest()))
    encrypted = AESGCM(secret).encrypt(nonce, canonical(session), aad)
    return {"context": context, "wrappedKey": b64(wrapped), "nonce": b64(nonce),
            "ciphertext": b64(encrypted)}


class SessionChannel:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.public_key_der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.challenges = {}
        self.lock = threading.Lock()

    def challenge(self, attempt, binding_digest):
        # Only admitted requests may reach this method. No unlimited public hello endpoint.
        with self.lock:
            self.challenges = {k: v for k, v in self.challenges.items() if v["expiresAt"] > time.time()}
            require(len(self.challenges) < 100, "capacity")
            context = {"protocol": "openplaid-session-v1", "attempt": attempt,
                       "bindingDigest": binding_digest, "nonce": secrets.token_hex(32),
                       "expiresAt": int(time.time()) + 120}
            self.challenges[context["nonce"]] = context
            return dict(context)

    def decrypt_once(self, envelope):
        fields(envelope, ("context", "wrappedKey", "nonce", "ciphertext"))
        context = envelope["context"]
        require(isinstance(context, dict) and isinstance(context.get("nonce"), str), "invalid_context")
        with self.lock:
            expected = self.challenges.pop(context["nonce"], None)
        # Burn the challenge even on invalid ciphertext. A retry needs admission again.
        require(expected is not None and expected == context and context["expiresAt"] > time.time(),
                "expired_or_replayed_challenge")
        try:
            aad = canonical(context)
            secret = self.key.decrypt(unb64(envelope["wrappedKey"], 512), padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                label=hashlib.sha256(aad).digest()))
            nonce = unb64(envelope["nonce"], 12)
            require(len(nonce) == 12, "invalid_nonce")
            plain = AESGCM(secret).decrypt(nonce, unb64(envelope["ciphertext"], 16400), aad)
            return strict_json(plain, 16384)
        except Exception as error:
            raise Rejected("invalid_envelope") from error
