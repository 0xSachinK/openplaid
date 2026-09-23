import base64
import copy
import hashlib
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from verification.common import Rejected, canonical
from verification.nvidia import ISSUER, verify_gpu_evidence


def enc(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


class NvidiaTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP384R1())
        p = self.key.public_key().public_numbers()
        self.jwks = {'keys': [{'kid': 'test', 'kty': 'EC', 'crv': 'P-384',
                              'x': enc(p.x.to_bytes(48, 'big')), 'y': enc(p.y.to_bytes(48, 'big'))}]}
        self.nonce = '12' * 32
        self.base = {'iss': ISSUER, 'iat': 990, 'nbf': 990, 'exp': 1100, 'eat_nonce': self.nonce}
        self.gpu = {**self.base, 'secboot': True, 'dbgstat': 'disabled', 'measres': 'success',
                    'x-nvidia-gpu-attestation-report-nonce-match': True,
                    'x-nvidia-gpu-attestation-report-signature-verified': True,
                    'x-nvidia-gpu-attestation-report-cert-chain-validated': True}

    def sign(self, claims, header=None):
        body = enc(canonical(header or {'kid': 'test', 'alg': 'ES384'})) + '.' + enc(canonical(claims))
        r, s = decode_dss_signature(self.key.sign(body.encode(), ec.ECDSA(hashes.SHA384())))
        return body + '.' + enc(r.to_bytes(48, 'big') + s.to_bytes(48, 'big'))

    def bundle(self, gpu=None, overall=True):
        token = self.sign(self.gpu if gpu is None else gpu)
        platform = {**self.base, 'sub': 'NVIDIA-PLATFORM-ATTESTATION',
                    'x-nvidia-overall-att-result': overall,
                    'submods': {'GPU-0': ['DIGEST', ['SHA-256', hashlib.sha256(token.encode()).hexdigest()]]}}
        return [['JWT', self.sign(platform)], {'GPU-0': token}]

    def verify(self, tokens, **kwargs):
        return verify_gpu_evidence(tokens, self.jwks, nonce=kwargs.get('nonce', self.nonce),
                                   gpu_count=kwargs.get('gpu_count', 1), now=kwargs.get('now', 1000))

    def test_valid_signed_bundle_does_not_claim_cpu_linkage(self):
        result = self.verify(self.bundle())
        self.assertTrue(result['gpuEvidenceVerified'])
        self.assertFalse(result['cpuGpuLinkageVerified'])
        self.assertFalse(result['readyForPrivateData'])

    def test_forged_signature_wrong_key_and_duplicate_kid_fail(self):
        tokens = self.bundle()
        parts = tokens[0][1].split('.')
        parts[2] = enc(b'\x00' * 96)
        tokens[0][1] = '.'.join(parts)
        with self.assertRaises(Rejected): self.verify(tokens)
        tokens = self.bundle()
        self.jwks['keys'][0]['x'] = enc(b'\x01' * 48)
        with self.assertRaises(Rejected): self.verify(tokens)
        self.jwks['keys'].append(copy.deepcopy(self.jwks['keys'][0]))
        with self.assertRaisesRegex(Rejected, 'unknown_nras_key'): self.verify(tokens)

    def test_signed_failure_debug_and_nonce_mismatch_fail(self):
        with self.assertRaises(Rejected): self.verify(self.bundle(overall=False))
        for delta in [{'dbgstat': 'enabled'}, {'eat_nonce': '34' * 32}, {'secboot': False},
                      {'measres': 'failure'}, {'x-nvidia-attestation-warning': 'warning'},
                      {'x-nvidia-gpu-attestation-report-cert-chain-validated': False}]:
            with self.assertRaises(Rejected): self.verify(self.bundle({**self.gpu, **delta}))
        with self.assertRaises(Rejected): self.verify(self.bundle(), nonce='56' * 32)

    def test_detached_substitution_and_missing_device_fail(self):
        tokens = self.bundle()
        tokens[1]['GPU-0'] = self.sign({**self.gpu, 'jti': 'different-signed-device'})
        with self.assertRaisesRegex(Rejected, 'nras_detached_digest_mismatch'): self.verify(tokens)
        with self.assertRaises(Rejected): self.verify(self.bundle(), gpu_count=2)

    def test_expiry_issuer_and_header_confusion_fail(self):
        with self.assertRaises(Rejected): self.verify(self.bundle(), now=1101)
        with self.assertRaises(Rejected): self.verify(self.bundle({**self.gpu, 'iss': 'attacker'}))
        for header in [{'alg': 'none', 'kid': 'test'}, {'alg': 'ES384', 'kid': 'test', 'jku': ISSUER}]:
            tokens = self.bundle()
            tokens[0][1] = self.sign(self.base, header)
            with self.assertRaisesRegex(Rejected, 'invalid_nras_algorithm'): self.verify(tokens)
