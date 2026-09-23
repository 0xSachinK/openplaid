"""Verify detached NVIDIA NRAS v3 EATs; this does not prove CPU/GPU linkage.

JWKS must be obtained from NVIDIA's fixed HTTPS endpoint by trusted operator code,
never from a token's jku/x5u or a model-provided URL. No network or inference here.
"""
import base64
import hashlib
import re
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .common import Rejected, hex_digest, require, strict_json

ISSUER = 'https://nras.attestation.nvidia.com'
JWKS_URL = ISSUER + '/.well-known/jwks.json'
ATTEST_URL = ISSUER + '/v3/attest/gpu'


def unurl(value):
    require(isinstance(value, str) and 0 < len(value) <= 65536 and
            re.fullmatch(r'[A-Za-z0-9_-]+', value) is not None, 'invalid_nras_encoding')
    try:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except ValueError as error:
        raise Rejected('invalid_nras_encoding') from error
    require(base64.urlsafe_b64encode(raw).decode().rstrip('=') == value,
            'invalid_nras_encoding')
    return raw


def verify_jwt(token, jwks, *, nonce, now):
    require(isinstance(token, str) and len(token) <= 65536, 'invalid_nras_token')
    parts = token.split('.')
    require(len(parts) == 3, 'invalid_nras_token')
    header = strict_json(unurl(parts[0]), 4096)
    require(isinstance(header, dict) and set(header) <= {'alg', 'kid', 'typ'} and
            header.get('alg') == 'ES384' and isinstance(header.get('kid'), str) and
            0 < len(header['kid']) <= 256 and header.get('typ', 'JWT') == 'JWT',
            'invalid_nras_algorithm')
    require(isinstance(jwks, dict) and isinstance(jwks.get('keys'), list) and
            1 <= len(jwks['keys']) <= 256, 'invalid_nras_jwks')
    matches = [k for k in jwks['keys'] if isinstance(k, dict) and k.get('kid') == header['kid']]
    require(len(matches) == 1, 'unknown_nras_key')
    key = matches[0]
    require(key.get('kty') == 'EC' and key.get('crv') == 'P-384' and
            key.get('use', 'sig') == 'sig' and key.get('alg', 'ES384') == 'ES384' and
            key.get('key_ops', ['verify']) == ['verify'], 'invalid_nras_key')
    x, y, signature = unurl(key.get('x')), unurl(key.get('y')), unurl(parts[2])
    require(len(x) == len(y) == 48 and len(signature) == 96, 'invalid_nras_signature')
    try:
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(x, 'big'), int.from_bytes(y, 'big'),
                                              ec.SECP384R1()).public_key()
        der = encode_dss_signature(int.from_bytes(signature[:48], 'big'),
                                   int.from_bytes(signature[48:], 'big'))
        public.verify(der, (parts[0] + '.' + parts[1]).encode('ascii'), ec.ECDSA(hashes.SHA384()))
    except Exception as error:
        raise Rejected('invalid_nras_signature') from error
    claims = strict_json(unurl(parts[1]), 49152)
    require(isinstance(claims, dict) and claims.get('iss') == ISSUER, 'invalid_nras_issuer')
    require(all(type(claims.get(k)) is int for k in ('iat', 'nbf', 'exp')),
            'invalid_nras_time')
    require(now - 300 <= claims['iat'] <= now + 5 and claims['nbf'] <= now and
            now < claims['exp'] <= claims['iat'] + 3600 and claims['nbf'] <= claims['exp'],
            'expired_nras_token')
    require(claims.get('eat_nonce') == nonce, 'nras_nonce_mismatch')
    return claims


def verify_gpu_evidence(tokens, jwks, *, nonce, gpu_count, now=None):
    """Return minimal evidence status, never workload approval or private-data consent."""
    hex_digest(nonce)
    now = time.time() if now is None else now
    require(type(gpu_count) is int and 1 <= gpu_count <= 8, 'invalid_gpu_count')
    require(isinstance(tokens, list) and len(tokens) == 2 and
            isinstance(tokens[0], list) and len(tokens[0]) == 2 and tokens[0][0] == 'JWT' and
            isinstance(tokens[1], dict), 'invalid_nras_bundle')
    platform = verify_jwt(tokens[0][1], jwks, nonce=nonce, now=now)
    require(platform.get('sub') == 'NVIDIA-PLATFORM-ATTESTATION' and
            platform.get('x-nvidia-overall-att-result') is True, 'gpu_attestation_failed')
    expected = {'GPU-' + str(i) for i in range(gpu_count)}
    submods = platform.get('submods')
    require(isinstance(submods, dict) and set(submods) == set(tokens[1]) == expected,
            'nras_gpu_set_mismatch')
    for name in sorted(expected):
        token = tokens[1][name]
        claims = verify_jwt(token, jwks, nonce=nonce, now=now)
        require(submods[name] == ['DIGEST', ['SHA-256', hashlib.sha256(token.encode()).hexdigest()]],
                'nras_detached_digest_mismatch')
        require(claims.get('secboot') is True and claims.get('dbgstat') == 'disabled' and
                claims.get('measres') == 'success' and
                claims.get('x-nvidia-gpu-attestation-report-nonce-match') is True and
                claims.get('x-nvidia-gpu-attestation-report-signature-verified') is True and
                claims.get('x-nvidia-gpu-attestation-report-cert-chain-validated') is True and
                claims.get('x-nvidia-attestation-warning') is None, 'gpu_attestation_failed')
    return {'gpuEvidenceVerified': True, 'gpuCount': gpu_count,
            'cpuGpuLinkageVerified': False, 'readyForPrivateData': False}
