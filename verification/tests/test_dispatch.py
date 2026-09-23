import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verification.common import Rejected, digest
from verification.control import Ledger


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'ledger'
        self.db = Ledger(self.path)
        self.key = Ed25519PrivateKey.generate()
        self.release = {'status': 'approved', 'liveVerification': True,
                        'expiresAt': int(time.time()) + 300, 'policyDigest': 'b' * 64}
        self.binding = {'revision': 'a' * 64, 'release': digest(self.release),
                        'policy': 'b' * 64, 'prompt': 'c' * 64}
        ticket = self.db.create_ticket(award='synthetic-issue', contributor='synthetic',
            revision='a' * 64, capability='synthetic/bank', expires=int(time.time()) + 300)
        self.ticket = ticket['id']
        self.db.judge(self.ticket, actor='operator', version=0, decision='admit', evidence_digest='d' * 64)
        self.attempt = self.db.reserve(self.ticket, 'request-1', self.binding, 40000)['id']
        self.context = {'protocol': 'openplaid-session-v1', 'attempt': self.attempt,
                        'bindingDigest': digest(self.binding), 'nonce': 'e' * 64,
                        'expiresAt': int(time.time()) + 60}
        self.args = {'context': self.context, 'attestation': b'synthetic-test-quote',
                     'public_key_der': b'synthetic-test-key', 'release': self.release,
                     'binding': self.binding, 'private_key': self.key}
        # Controller transaction tests only. Real quote cryptography is tested separately.
        self.quote = patch('verification.control.verify_document')
        self.verify = self.quote.start()

    def tearDown(self):
        self.quote.stop()
        self.db.db.close()
        self.temp.cleanup()

    def issue(self, **changes):
        self.admission()
        return self.db.authorize_execution(self.attempt, **{**self.args, **changes})

    def admission(self, ledger=None, **changes):
        args = {k: v for k, v in self.args.items() if k != 'context'}
        return (ledger or self.db).authorize_challenge(self.attempt, **{**args, 'nonce': b'n' * 32, **changes})

    def test_concurrent_challenge_authorization_is_durable(self):
        def issue(_):
            ledger = Ledger(self.path)
            try:
                return self.admission(ledger)
            finally:
                ledger.db.close()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(issue, range(8)))
        self.assertTrue(all(value == results[0] for value in results))
        self.assertEqual(self.db.db.execute('SELECT COUNT(*) FROM challenge_grants').fetchone()[0], 1)
        self.assertEqual(self.db.status()['budget']['committed'], 40000)
        self.verify.assert_called_with(b'synthetic-test-quote', nonce=b'n' * 32,
                                      public_key_der=b'synthetic-test-key', release=self.release)

    def test_challenge_cannot_move_to_new_enclave_or_extend_expiry(self):
        grant = self.admission()
        with self.assertRaisesRegex(Rejected, 'admission_already_issued'):
            self.admission(public_key_der=b'new-key')
        with patch('verification.admission.time.time', return_value=grant['claims']['expiresAt'] + 1):
            with self.assertRaisesRegex(Rejected, 'admission_expired'):
                self.admission()
        self.assertEqual(self.db.db.execute('SELECT COUNT(*) FROM challenge_grants').fetchone()[0], 1)

    def test_challenge_refuses_bad_quote_binding_or_paused_service(self):
        self.verify.side_effect = Rejected('invalid_attestation')
        with self.assertRaisesRegex(Rejected, 'invalid_attestation'):
            self.admission()
        self.verify.side_effect = None
        with self.assertRaisesRegex(Rejected, 'permit_binding'):
            self.admission(binding={**self.binding, 'revision': 'f' * 64})
        self.db.pause()
        with self.assertRaisesRegex(Rejected, 'service_paused'):
            self.admission()
        self.assertEqual(self.db.db.execute('SELECT COUNT(*) FROM challenge_grants').fetchone()[0], 0)

    def test_challenge_refuses_finished_attempt(self):
        self.admission()
        self.db.finish(self.attempt, 'blocked')
        with self.assertRaisesRegex(Rejected, 'attempt_not_reserved'):
            self.admission()

    def test_challenge_refuses_revoked_attempt(self):
        self.admission()
        self.db.judge(self.ticket, actor='operator', version=1, decision='revoke', evidence_digest='d' * 64)
        with self.assertRaisesRegex(Rejected, 'ticket_not_admitted'):
            self.admission()

    def test_retry_returns_same_permit_without_extra_budget(self):
        first = self.issue()
        self.assertEqual(first, self.issue())
        self.assertEqual(first['claims']['maximumMicroUsd'], 40000)
        self.assertEqual(first['claims']['artifactDigest'], 'a' * 64)
        self.assertEqual(self.db.status()['budget']['committed'], 40000)
        self.verify.assert_called_with(b'synthetic-test-quote', nonce=bytes.fromhex(digest(self.context)),
                                      public_key_der=b'synthetic-test-key', release=self.release)

    def test_changed_challenge_or_enclave_cannot_remint(self):
        self.issue()
        for changes in ({'context': {**self.context, 'nonce': 'f' * 64}},
                        {'public_key_der': b'other-enclave-key'}):
            with self.assertRaisesRegex(Rejected, 'permit_already_issued'):
                self.issue(**changes)

    def test_pause_revocation_and_finished_attempt_block_issuance(self):
        self.issue()
        self.db.pause()
        with self.assertRaisesRegex(Rejected, 'service_paused'):
            self.issue()
        self.db.judge(self.ticket, actor='operator', version=1, decision='revoke', evidence_digest='d' * 64)
        with self.assertRaisesRegex(Rejected, 'ticket_not_admitted'):
            self.issue()

    def test_failure_reconciliation_prevents_new_permit(self):
        self.db.finish(self.attempt, 'blocked')
        with self.assertRaisesRegex(Rejected, 'attempt_not_reserved'):
            self.issue()

    def test_bad_quote_and_binding_leave_no_permit(self):
        self.verify.side_effect = Rejected('invalid_attestation')
        with self.assertRaisesRegex(Rejected, 'invalid_attestation'):
            self.issue()
        self.verify.side_effect = None
        with self.assertRaisesRegex(Rejected, 'permit_binding'):
            self.issue(context={**self.context, 'bindingDigest': 'f' * 64})
        self.assertEqual(self.db.db.execute('SELECT COUNT(*) FROM execution_permits').fetchone()[0], 0)

    def test_concurrent_controllers_persist_one_permit(self):
        self.admission()
        def issue(_):
            ledger = Ledger(self.path)
            try:
                return ledger.authorize_execution(self.attempt, **self.args)
            finally:
                ledger.db.close()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(issue, range(8)))
        self.assertTrue(all(value == results[0] for value in results))
        self.assertEqual(self.db.db.execute('SELECT COUNT(*) FROM execution_permits').fetchone()[0], 1)

    def test_execution_requires_prior_matching_challenge_authorization(self):
        with self.assertRaisesRegex(Rejected, 'admission_required'):
            self.db.authorize_execution(self.attempt, **self.args)
        self.admission(public_key_der=b'other-key')
        with self.assertRaisesRegex(Rejected, 'admission_binding'):
            self.db.authorize_execution(self.attempt, **self.args)
