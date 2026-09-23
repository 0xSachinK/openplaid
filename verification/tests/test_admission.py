import hashlib
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verification.admission import issue
from verification.channel import SessionChannel, encrypt_session
from verification.common import Rejected
from verification.permits import verify as verify_execution


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.channel = SessionChannel()
        self.signer = Ed25519PrivateKey.generate()
        self.public = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.claims = {'audience': 'openplaid-challenge-v1', 'attempt': 'synthetic',
                       'enclaveKeyDigest': hashlib.sha256(self.channel.public_key_der).hexdigest(),
                       'bindingDigest': 'b' * 64, 'policyDigest': 'c' * 64,
                       'expiresAt': int(time.time()) + 60}
        self.grant = issue(self.claims, self.signer)

    def challenge(self, grant=None, channel=None):
        return (channel or self.channel).challenge_authorized(
            self.grant if grant is None else grant, operator_public_key=self.public, policy_digest='c' * 64)

    def test_concurrent_retries_allocate_one_challenge(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.challenge(), range(16)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(len(self.channel.challenges), 1)
        self.assertEqual(results[0]['expiresAt'], self.claims['expiresAt'])

    def test_signature_key_policy_and_expiry_fail_before_allocation(self):
        wrong = issue(self.claims, Ed25519PrivateKey.generate())
        for grant in (wrong, issue({**self.claims, 'policyDigest': 'd' * 64}, self.signer)):
            with self.assertRaises(Rejected):
                self.challenge(grant)
        with self.assertRaisesRegex(Rejected, 'admission_binding'):
            self.challenge(channel=SessionChannel())
        with patch('verification.admission.time.time', return_value=self.claims['expiresAt']):
            with self.assertRaisesRegex(Rejected, 'admission_expired'):
                self.challenge()
        self.assertFalse(self.channel.challenges)
        self.assertFalse(self.channel.admissions)

    def test_consumption_and_bad_ciphertext_cannot_remint(self):
        context = self.challenge()
        envelope = encrypt_session(self.channel.public_key_der, context, {'synthetic': True}, consent=True)
        with self.assertRaisesRegex(Rejected, 'invalid_envelope'):
            self.channel.decrypt_once({**envelope, 'ciphertext': 'AAAA'})
        with self.assertRaisesRegex(Rejected, 'admission_consumed'):
            self.challenge()
        # Even a second signed grant cannot replace the attempt's original context.
        changed = issue({**self.claims, 'bindingDigest': 'e' * 64}, self.signer)
        with self.assertRaisesRegex(Rejected, 'admission_already_issued'):
            self.challenge(changed)

    def test_spent_tombstones_count_towards_capacity(self):
        for i in range(100):
            context = self.challenge(issue({**self.claims, 'attempt': f'synthetic-{i}'}, self.signer))
            self.channel.challenges.pop(context['nonce'])  # Simulate an already consumed challenge.
        with self.assertRaisesRegex(Rejected, 'capacity'):
            self.challenge()
        self.assertEqual(len(self.channel.admissions), 100)

    def test_challenge_grant_is_not_an_execution_permit(self):
        with self.assertRaises(Rejected):
            verify_execution(self.grant, self.public, enclave_key_digest=self.claims['enclaveKeyDigest'],
                             policy_digest='c' * 64, artifact_digest='a' * 64, challenge='f' * 64)
