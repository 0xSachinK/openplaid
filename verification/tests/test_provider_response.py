import hashlib
import unittest

from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from verification.common import Rejected
from verification.provider_diagnostic import legacy_response_binding


class ProviderResponseTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256K1())
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.request = b'{"synthetic":true}'
        self.response = b'data: synthetic-test\n\ndata: [DONE]\n\n'
        text = hashlib.sha256(self.request).hexdigest() + ':' + hashlib.sha256(self.response).hexdigest()
        prehash = keccak.new(digest_bits=256, data=b'\x19Ethereum Signed Message:\n129' + text.encode()).digest()
        r, s = utils.decode_dss_signature(self.key.sign(prehash, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
        self.signature = {'text': text, 'signing_algo': 'ecdsa',
            'signing_address': '0x' + keccak.new(digest_bits=256, data=self.public[1:]).digest()[-20:].hex(),
            'signature': '0x' + (r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + b'\x1b').hex()}

    def verify(self, **changes):
        args = {'public_key': self.public, 'request_bytes': self.request, 'response_bytes': self.response}
        return legacy_response_binding(self.signature, **{**args, **changes})

    def test_matching_signature_and_bytes_do_not_approve_private_data(self):
        result = self.verify()
        self.assertTrue(result['requestResponseBound'])
        self.assertFalse(result['readyForPrivateData'])

    def test_valid_signature_cannot_authenticate_changed_request_or_stream(self):
        for changes in ({'request_bytes': b'other'}, {'response_bytes': self.response[:-1]},
                        {'response_bytes': self.response + b'data: injected\n\n'}):
            with self.subTest(changes=changes), self.assertRaisesRegex(Rejected, 'provider_response_binding_mismatch'):
                self.verify(**changes)

    def test_other_key_address_and_bad_signature_fail(self):
        other = ec.generate_private_key(ec.SECP256K1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        with self.assertRaises(Rejected):
            self.verify(public_key=other)
        original = dict(self.signature)
        for field, value in (('signature', '0x' + '00' * 65), ('signing_address', '0x' + '00' * 20),
                             ('text', '0' * 64 + ':' + '1' * 64)):
            self.signature = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify()

    def test_unsigned_receipt_metadata_cannot_change_binding_result(self):
        self.signature['receipt'] = {'upstream': 'attacker-selected', 'verified': True}
        self.assertEqual(self.verify(), {'legacySignatureVerified': True, 'requestResponseBound': True,
                                        'readyForPrivateData': False})
