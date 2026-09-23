import hashlib
import unittest

from verification.common import Rejected, canonical
from verification.provider_diagnostic import aci_binding


class AciBindingTests(unittest.TestCase):
    def setUp(self):
        self.nonce = 'ab' * 32
        keyset = {'subject': None, 'not_after': 200,
                  'e2ee_public_keys': [{'key_id': 'example', 'public_key': '04' + 'cd' * 64}]}
        digest = 'sha256:' + hashlib.sha256(canonical(keyset)).hexdigest()
        self.data = hashlib.sha256(canonical({'keyset_digest': digest, 'nonce': self.nonce,
                                              'purpose': 'aci.report_data.v1'})).hexdigest() + '0' * 64
        self.report = {'api_version': 'aci/1', 'nonce': self.nonce,
                       'workload_keyset_digest': digest,
                       'attestation': {'workload_keyset': keyset, 'report_data': self.data},
                       'verified': True}

    def check(self, data=None, nonce=None):
        return aci_binding(self.report, quote_report_data=data or self.data,
                           nonce=nonce or self.nonce, now=100)

    def test_bound_nonce_and_keyset(self):
        self.assertTrue(self.check()['nonceAndKeysetBound'])
        self.report['verified'] = False  # Server claims have no authority.
        self.assertTrue(self.check()['nonceAndKeysetBound'])

    def test_server_verified_cannot_replace_quote_binding(self):
        with self.assertRaisesRegex(Rejected, 'provider_quote_binding_mismatch'):
            self.check(data='00' * 64)

    def test_wrong_nonce_or_replaced_key_rejected(self):
        with self.assertRaisesRegex(Rejected, 'provider_nonce_mismatch'):
            self.check(nonce='ef' * 32)
        self.report['attestation']['workload_keyset']['e2ee_public_keys'][0]['public_key'] = 'attacker'
        with self.assertRaisesRegex(Rejected, 'provider_keyset_mismatch'):
            self.check()
        # Rehashing the attacker-controlled JSON must still fail the signed binding.
        self.report['workload_keyset_digest'] = 'sha256:' + hashlib.sha256(
            canonical(self.report['attestation']['workload_keyset'])).hexdigest()
        with self.assertRaisesRegex(Rejected, 'provider_quote_binding_mismatch'):
            self.check()

    def test_expiry_unsafe_integer_and_unicode_rejected(self):
        keyset = self.report['attestation']['workload_keyset']
        for value in [100, 2**54, 200.0]:
            keyset['not_after'] = value
            with self.assertRaises(Rejected):
                self.check()
        keyset['not_after'] = 200
        keyset['subject'] = '\u2028'
        with self.assertRaisesRegex(Rejected, 'invalid_provider_keyset'):
            self.check()
