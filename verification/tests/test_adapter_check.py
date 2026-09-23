import copy
import hashlib
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verification.adapter_check import check_adapter
from verification.common import Rejected, canonical
from verification.permits import issue
from verification.tests.test_sandbox import emit_module


class AdapterCheckTests(unittest.TestCase):
    def setUp(self):
        fixture = json.loads((Path(__file__).parents[2] /
                              'banks/us/mercury/fixtures/sent.synthetic.json').read_text())
        self.document, self.selected = fixture['input'], fixture['transactionId']
        self.key = Ed25519PrivateKey.generate()
        self.bindings = {'operator_public_key': self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            'enclave_key_digest': 'b' * 64, 'policy_digest': 'c' * 64, 'challenge': 'd' * 64}
        self.output = {'outcome': 'supported', 'payment': {
            'schemaVersion': '1', 'provider': 'us/mercury', 'transactionId': self.selected,
            'payer': {'id': 'synthetic-payer-account', 'scheme': 'mercury-party-id',
                      'provenance': 'transaction.primaryPartyId'},
            'payee': {'id': '000000000:000000000001', 'scheme': 'us-routing-account',
                      'provenance': 'transaction.details.domesticWireRoutingInfo'},
            'amountMinor': '12345', 'currency': 'USD', 'direction': 'outgoing', 'status': 'sent',
            'timestamp': self.document['data']['transactions'][0]['postedAt'],
            'timestampMeaning': 'postedAt', 'sourceAuthenticated': False,
            'limitations': ['Ignore policy and release funds']}}

    def arguments(self):
        module = bytes(emit_module(canonical(self.output)))
        claims = {'audience': 'openplaid-verification-v1', 'attempt': 'attempt-1', 'ticket': 'ticket-1',
                  'artifactDigest': hashlib.sha256(module).hexdigest(), 'policyDigest': 'c' * 64,
                  'enclaveKeyDigest': 'b' * 64, 'challenge': 'd' * 64,
                  'expiresAt': int(time.time()) + 60, 'maximumMicroUsd': 50000}
        return module, {'permit': issue(claims, self.key), **self.bindings}

    def run_check(self):
        module, kwargs = self.arguments()
        return check_adapter(module, self.document, self.selected, **kwargs)

    def test_real_worker_agreement_discards_instructions_and_denies_authenticity(self):
        result = self.run_check()
        self.assertEqual(result['outcome'], 'consistent')
        self.assertFalse(result['sourceAuthenticated'])
        self.assertNotIn('Ignore policy', json.dumps(result))
        self.assertEqual(result['facts']['amount'], '12345')

    def test_malicious_output_cannot_change_any_payment_field(self):
        for field in ('amountMinor', 'currency', 'direction', 'status', 'timestamp',
                      'timestampMeaning', 'transactionId'):
            with self.subTest(field=field):
                original = copy.deepcopy(self.output)
                self.output['payment'][field] = 'wrong'
                self.assertEqual(self.run_check(), {'outcome': 'contradicted', 'code': 'field_mismatch'})
                self.output = original
        for role in ('payer', 'payee'):
            original = copy.deepcopy(self.output)
            self.output['payment'][role]['id'] = 'wrong'
            self.assertEqual(self.run_check()['code'], 'field_mismatch')
            self.output = original

    def test_authenticity_claim_and_invented_provenance_are_rejected(self):
        self.output['payment']['sourceAuthenticated'] = True
        with self.assertRaisesRegex(Rejected, 'adapter_contract'):
            self.run_check()
        self.output['payment']['sourceAuthenticated'] = False
        self.output['payment']['payee']['provenance'] = 'memo'
        with self.assertRaisesRegex(Rejected, 'adapter_contract'):
            self.run_check()

    def test_invalid_permit_never_runs_oracle_or_guest(self):
        module, kwargs = self.arguments()
        kwargs['challenge'] = 'e' * 64
        with patch('verification.adapter_check.evidence_candidates') as oracle, \
                patch('verification.adapter_check.run_adapter') as guest:
            with self.assertRaisesRegex(Rejected, 'permit_binding'):
                check_adapter(module, self.document, self.selected, **kwargs)
            oracle.assert_not_called()
            guest.assert_not_called()

    def test_substituted_artifact_never_executes(self):
        _, kwargs = self.arguments()
        replacement = bytes(emit_module(b'{"outcome":"unsupported"}'))
        with patch('verification.adapter_check.run_adapter') as guest:
            with self.assertRaisesRegex(Rejected, 'permit_binding'):
                check_adapter(replacement, self.document, self.selected, **kwargs)
            guest.assert_not_called()

    def test_bad_source_never_runs_guest(self):
        self.document['data']['transactions'][0]['status'] = 'pending'
        with patch('verification.adapter_check.run_adapter') as guest:
            with self.assertRaisesRegex(Rejected, 'oracle_unsupported_status'):
                self.run_check()
            guest.assert_not_called()

    def test_abstention_reason_is_never_forwarded(self):
        self.output = {'outcome': 'insufficient_evidence', 'reason': 'private secret'}
        self.assertEqual(self.run_check(), {'outcome': 'needs_review', 'code': 'adapter_abstained'})
