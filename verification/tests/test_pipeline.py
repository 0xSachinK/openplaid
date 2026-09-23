import hashlib
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verification.channel import SessionChannel, encrypt_session
from verification.common import Rejected, canonical
from verification.mercury_oracle import CAPABILITY
from verification.permits import issue
from verification.pipeline import acquire_and_compare
from verification.tests import test_adapter_check as adapter_fixtures
from verification.tests.test_sandbox import emit_module


class PipelineTests(unittest.TestCase):
    def setUp(self):
        fixture = adapter_fixtures.AdapterCheckTests()
        fixture.setUp()
        self.document = fixture.document
        self.module = bytes(emit_module(canonical(fixture.output)))
        self.channel = SessionChannel()
        self.key = Ed25519PrivateKey.generate()
        self.context = self.channel.challenge('attempt-1', 'a' * 64)
        self.session = {'credentials': {'cookie': 'synthetic-only'},
                        'sourceContext': {'organizationId': '00000000-0000-0000-0000-000000000000'},
                        'transactionId': fixture.selected}
        self.envelope = self.encrypt(self.session)
        self.permit = issue({'audience': 'openplaid-verification-v1', 'attempt': 'attempt-1',
            'ticket': 'ticket-1', 'artifactDigest': hashlib.sha256(self.module).hexdigest(),
            'policyDigest': 'b' * 64, 'enclaveKeyDigest': hashlib.sha256(self.channel.public_key_der).hexdigest(),
            'challenge': self.context['nonce'], 'expiresAt': self.context['expiresAt'],
            'maximumMicroUsd': 50000}, self.key)
        self.trust = {'operator_public_key': self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw), 'policy_digest': 'b' * 64,
            'source_policy': {'enabled': True, 'status': 'approved', 'capability': CAPABILITY}}

    def encrypt(self, session):
        return encrypt_session(self.channel.public_key_der, self.context, session, consent=True)

    def execute(self, **changes):
        return acquire_and_compare(self.channel, changes.get('module', self.module),
            changes.get('envelope', self.envelope), self.permit, **self.trust)

    def test_real_crypto_and_wasm_with_synthetic_acquisition_runs_once(self):
        # Only the acquisition boundary is mocked: this proves composition, not bank TLS.
        with patch('verification.pipeline.fetch_source_isolated', return_value=self.document) as fetch:
            result = self.execute()
            self.assertEqual(result['outcome'], 'consistent')
            self.assertTrue(result['sourceAuthenticated'])
            self.assertEqual(result['facts']['amount'], '12345')
            self.assertNotIn('credentials', result)
            self.assertNotIn('Ignore policy', str(result))
            fetch.assert_called_once_with(self.trust['source_policy'], self.session['credentials'],
                source_context=self.session['sourceContext'], transport='nitro')
            with self.assertRaisesRegex(Rejected, 'expired_or_replayed_challenge'):
                self.execute()
            self.assertEqual(fetch.call_count, 1)

    def test_wrong_artifact_never_decrypts_or_fetches(self):
        with patch('verification.pipeline.fetch_source_isolated') as fetch:
            with self.assertRaisesRegex(Rejected, 'permit_binding'):
                self.execute(module=bytes(emit_module(b'{}')))
            fetch.assert_not_called()
        self.assertIn(self.context['nonce'], self.channel.challenges)

    def test_disabled_policy_never_decrypts(self):
        self.trust['source_policy']['enabled'] = False
        with patch.object(self.channel, 'decrypt_authorized') as decrypt:
            with self.assertRaisesRegex(Rejected, 'source_policy_not_approved'):
                self.execute()
            decrypt.assert_not_called()

    def test_submitted_document_or_url_is_rejected_before_network(self):
        for field in ('document', 'url', 'prompt', 'requestBody'):
            self.setUp()
            with self.subTest(field=field), patch('verification.pipeline.fetch_source_isolated') as fetch:
                with self.assertRaisesRegex(Rejected, 'invalid_fields'):
                    self.execute(envelope=self.encrypt({**self.session, field: 'untrusted'}))
                fetch.assert_not_called()
                self.assertNotIn(self.context['nonce'], self.channel.challenges)

    def test_failed_bank_read_is_not_retried_and_guest_never_runs(self):
        with patch('verification.pipeline.fetch_source_isolated', side_effect=Rejected('bank_read_timeout')) as fetch, \
                patch('verification.pipeline.check_adapter') as guest:
            with self.assertRaisesRegex(Rejected, 'bank_read_timeout'):
                self.execute()
            with self.assertRaisesRegex(Rejected, 'expired_or_replayed_challenge'):
                self.execute()
            fetch.assert_called_once()
            guest.assert_not_called()

    def test_expired_permit_after_bank_read_prevents_guest_execution(self):
        def acquired(*args, **kwargs):
            clock = patch('verification.permits.time.time',
                          return_value=self.permit['claims']['expiresAt'] + 1)
            clock.start()
            self.addCleanup(clock.stop)
            return self.document
        with patch('verification.pipeline.fetch_source_isolated', side_effect=acquired), \
                patch('verification.adapter_check.run_adapter') as guest:
            with self.assertRaisesRegex(Rejected, 'permit_expired'):
                self.execute()
            guest.assert_not_called()
