import hashlib
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verification.channel import SessionChannel, encrypt_session
from verification.common import Rejected
from verification.permits import issue


class AuthorizedChannelTests(unittest.TestCase):
    def setUp(self):
        self.channel = SessionChannel()
        self.signer = Ed25519PrivateKey.generate()
        self.context = self.channel.challenge('synthetic-attempt', 'd' * 64)
        self.envelope = encrypt_session(self.channel.public_key_der, self.context,
                                       {'syntheticCredential': 'test-only'}, consent=True)
        self.claims = {'audience': 'openplaid-verification-v1', 'attempt': 'synthetic-attempt',
                       'ticket': 'synthetic-ticket', 'artifactDigest': 'a' * 64, 'policyDigest': 'b' * 64,
                       'enclaveKeyDigest': hashlib.sha256(self.channel.public_key_der).hexdigest(),
                       'challenge': self.context['nonce'], 'expiresAt': int(time.time()) + 60,
                       'maximumMicroUsd': 1000}
        self.permit = issue(self.claims, self.signer)
        self.trust = {'operator_public_key': self.signer.public_key().public_bytes(
                         serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                      'policy_digest': 'b' * 64, 'artifact_digest': 'a' * 64}

    def decrypt(self, envelope=None, permit=None):
        return self.channel.decrypt_authorized(self.envelope if envelope is None else envelope,
                    self.permit if permit is None else permit, **self.trust)

    def test_concurrent_replay_decrypts_exactly_once(self):
        def attempt(_):
            try:
                return self.decrypt()
            except Rejected:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(16)))
        self.assertEqual(results.count({'syntheticCredential': 'test-only'}), 1)
        self.assertEqual(results.count(None), 15)

    def test_bad_signature_does_not_burn_valid_challenge(self):
        wrong_signer = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(Rejected, 'invalid_permit_signature'):
            self.decrypt(permit=issue(self.claims, wrong_signer))
        self.assertEqual(self.decrypt(), {'syntheticCredential': 'test-only'})

    def test_authorized_bad_ciphertext_burns_challenge(self):
        with self.assertRaisesRegex(Rejected, 'invalid_envelope'):
            self.decrypt(envelope={**self.envelope, 'ciphertext': 'AAAA'})
        with self.assertRaisesRegex(Rejected, 'expired_or_replayed_challenge'):
            self.decrypt()

    def test_wrong_artifact_policy_attempt_or_key_rejected(self):
        for field, value in (('artifactDigest', 'c' * 64), ('policyDigest', 'c' * 64),
                             ('enclaveKeyDigest', 'c' * 64), ('attempt', 'other-attempt')):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.decrypt(permit=issue({**self.claims, field: value}, self.signer))
        self.assertEqual(self.decrypt(), {'syntheticCredential': 'test-only'})

    def test_runtime_restart_rejects_old_permit(self):
        restarted = SessionChannel()
        with self.assertRaisesRegex(Rejected, 'permit_binding'):
            restarted.decrypt_authorized(self.envelope, self.permit, **self.trust)
