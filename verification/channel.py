"""One-use, context-bound hybrid encryption after attestation and explicit consent."""
import hashlib
import secrets
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import Rejected, b64, canonical, digest, fields, hex_digest, require, strict_json, unb64
from .admission import verify as verify_admission
from .permits import verify as verify_permit


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
        self.admissions = {}
        self.lock = threading.Lock()

    def challenge_authorized(self, grant, *, operator_public_key, policy_digest):
        """Measured configuration supplies trust, never the submitter.

        Keep spent-attempt tombstones until grant expiry. Replaying a grant can
        neither allocate another challenge nor undo consumption of the first one.
        """
        claims = verify_admission(grant, operator_public_key,
            enclave_key_digest=hashlib.sha256(self.public_key_der).hexdigest(), policy_digest=policy_digest)
        with self.lock:
            now = time.time()
            require(claims["expiresAt"] > now, "admission_expired")
            self.admissions = {k: v for k, v in self.admissions.items() if v["context"]["expiresAt"] > now}
            self.challenges = {k: v for k, v in self.challenges.items() if v["expiresAt"] > now}
            prior = self.admissions.get(claims["attempt"])
            if prior:
                require(prior["digest"] == digest(grant), "admission_already_issued")
                require(prior["context"]["nonce"] in self.challenges, "admission_consumed")
                return dict(prior["context"])
            require(len(self.admissions) < 100 and len(self.challenges) < 100, "capacity")
            context = {"protocol": "openplaid-session-v1", "attempt": claims["attempt"],
                       "bindingDigest": claims["bindingDigest"], "nonce": secrets.token_hex(32),
                       "expiresAt": claims["expiresAt"]}
            self.admissions[claims["attempt"]] = {"digest": digest(grant), "context": context}
            self.challenges[context["nonce"]] = context
            return dict(context)

    def challenge(self, attempt, binding_digest):
        # Low-level component/test helper. Live callers must use challenge_authorized.
        with self.lock:
            self.challenges = {k: v for k, v in self.challenges.items() if v["expiresAt"] > time.time()}
            require(len(self.challenges) < 100, "capacity")
            context = {"protocol": "openplaid-session-v1", "attempt": attempt,
                       "bindingDigest": binding_digest, "nonce": secrets.token_hex(32),
                       "expiresAt": int(time.time()) + 120}
            self.challenges[context["nonce"]] = context
            return dict(context)

    def decrypt_authorized(self, envelope, permit, *, operator_public_key, policy_digest,
                           artifact_digest):
        """Live-session boundary: trust inputs come from measured runtime configuration.

        Invalid permits never consume another user's challenge. A valid permit burns
        its challenge before decryption, including on malformed ciphertext. The lock
        in decrypt_once makes concurrent submissions mutually exclusive. The private
        RSA key is ephemeral: a restart invalidates all old permits and ciphertext.
        This method returns private session data only to the internal pipeline.
        """
        fields(envelope, ("context", "wrappedKey", "nonce", "ciphertext"))
        context = envelope["context"]
        fields(context, ("protocol", "attempt", "bindingDigest", "nonce", "expiresAt"))
        hex_digest(context["nonce"])
        require(context["protocol"] == "openplaid-session-v1" and
                type(context["expiresAt"]) is int, "invalid_context")
        claims = verify_permit(permit, operator_public_key,
                               enclave_key_digest=hashlib.sha256(self.public_key_der).hexdigest(),
                               policy_digest=policy_digest, artifact_digest=artifact_digest,
                               challenge=context["nonce"])
        require(claims["attempt"] == context["attempt"] and
                claims["expiresAt"] <= context["expiresAt"], "permit_context")
        return self.decrypt_once(envelope)

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
