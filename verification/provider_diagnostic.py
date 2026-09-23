"""Operator-only ACI/TDX diagnostics. Never returns an approved inference key.

The production runtime does not import this module. CPU verification and ACI binding
are necessary but insufficient: GPU, workload identity and custody remain separate gates.
"""
import argparse
import asyncio
import hashlib
import json
import time
from pathlib import Path

from Crypto.Hash import keccak
from cryptography.hazmat.primitives.asymmetric import ec

from .common import Rejected, canonical, hex_digest, require, strict_json


def aci_binding(report, *, quote_report_data, nonce, now):
    """Check ACI binding against report_data extracted by a cryptographic verifier.

    This helper alone does not authenticate a quote or authorize disclosure. Restrict
    JCS inputs to ASCII strings/keys and safe integers; Python JSON then has the same
    canonical bytes as the provider's documented RFC 8785 subset.
    """
    hex_digest(nonce)
    require(report.get('api_version') == 'aci/1', 'unsupported_provider_protocol')
    require(report.get('nonce') == nonce, 'provider_nonce_mismatch')
    attestation = report.get('attestation')
    require(isinstance(attestation, dict), 'missing_provider_attestation')
    keyset = attestation.get('workload_keyset')
    require(isinstance(keyset, dict), 'invalid_provider_keyset')

    def validate(value, depth=0):
        require(depth <= 8, 'invalid_provider_keyset')
        if value is None or type(value) is bool:
            return
        if type(value) is int:
            require(abs(value) <= 9007199254740991, 'invalid_provider_keyset')
        elif isinstance(value, str):
            require(value.isascii() and len(value) <= 4096, 'invalid_provider_keyset')
        elif isinstance(value, list):
            require(len(value) <= 32, 'invalid_provider_keyset')
            for item in value:
                validate(item, depth + 1)
        elif isinstance(value, dict):
            require(len(value) <= 32, 'invalid_provider_keyset')
            for key, item in value.items():
                require(isinstance(key, str) and key.isascii() and len(key) <= 80,
                        'invalid_provider_keyset')
                validate(item, depth + 1)
        else:
            raise Rejected('invalid_provider_keyset')

    validate(keyset)
    require(type(keyset.get('not_after')) is int and keyset['not_after'] > now,
            'expired_provider_keyset')
    keyset_bytes = json.dumps(keyset, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode()
    keyset_digest = 'sha256:' + hashlib.sha256(keyset_bytes).hexdigest()
    require(report.get('workload_keyset_digest') == keyset_digest, 'provider_keyset_mismatch')
    statement = canonical({'keyset_digest': keyset_digest, 'nonce': nonce,
                           'purpose': 'aci.report_data.v1'})
    expected = hashlib.sha256(statement).hexdigest() + '0' * 64
    require(quote_report_data == expected, 'provider_quote_binding_mismatch')
    require(attestation.get('report_data') == expected, 'provider_report_data_mismatch')
    return {'nonceAndKeysetBound': True, 'keysetDigest': keyset_digest}


def legacy_v1_binding(report, *, quote_report_data, nonce):
    """Check the explicitly selected dstack-vllm compatibility protocol.

    The address is derived from the curve-validated public key, never trusted as
    a substitute for it. This protocol binds one key, NOT the adjacent ACI keyset.
    """
    hex_digest(nonce)
    require(report.get('nonce') == nonce, 'provider_nonce_mismatch')
    require(report.get('signing_algo') == 'ecdsa', 'unsupported_provider_algorithm')
    key_hex = report.get('signing_public_key')
    require(isinstance(key_hex, str) and len(key_hex) == 130 and key_hex.startswith('04'),
            'invalid_provider_key')
    try:
        key = bytes.fromhex(key_hex)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), key)
    except ValueError as error:
        raise Rejected('invalid_provider_key') from error
    address = keccak.new(digest_bits=256, data=key[1:]).digest()[-20:].hex()
    require(report.get('signing_address', '').lower() == '0x' + address,
            'provider_address_mismatch')
    expected = address + '0' * 24 + nonce
    require(quote_report_data == expected, 'provider_quote_binding_mismatch')
    return {'nonceAndEncryptionKeyBound': True, 'nonceAndKeysetBound': False}


async def diagnose(report, nonce, binding_protocol='aci-v1'):
    # Optional pinned tool dependency, deliberately absent from the runtime lock.
    import dcap_qvl
    require(isinstance(report, dict), 'invalid_provider_report')
    require(binding_protocol in ('aci-v1', 'legacy-v1'), 'unsupported_provider_protocol')
    raw = report.get('intel_quote')
    require(isinstance(raw, str) and 0 < len(raw) <= 65536, 'invalid_provider_quote')
    try:
        quote = bytes.fromhex(raw)
    except ValueError as error:
        raise Rejected('invalid_provider_quote') from error
    now = int(time.time())
    collateral = await asyncio.wait_for(
        dcap_qvl.get_collateral(dcap_qvl.PHALA_PCCS_URL, quote), 30)
    verifier = dcap_qvl.QuoteVerifier()
    # claims_only still validates the Intel signature chain, collateral and quote.
    # Its output is diagnostic evidence, NEVER a replacement for strict policy.
    claims = json.loads(verifier.verify_with_policy(
        quote, collateral, now, dcap_qvl.QuotePolicy.claims_only(now)).to_json())
    result = {'schemaVersion': '1', 'cpuCryptographyVerified': True,
              'cpuStrictPolicyPassed': False, 'nonceAndKeysetBound': False,
              'readyForPrivateData': False, 'gpuVerified': False,
              'workloadIdentityApproved': False, 'keyCustodyVerified': False}
    result['bindingProtocol'] = binding_protocol
    try:
        verifier.verify_with_policy(quote, collateral, now, dcap_qvl.QuotePolicy.strict(now))
        result['cpuStrictPolicyPassed'] = True
    except ValueError:
        result['cpuPolicyError'] = 'strict_cpu_policy_rejected'
    reports = claims.get('report', {})
    require(claims.get('tee_type') == 129 and set(reports) == {'TD10'},
            'unsupported_provider_quote')
    try:
        if binding_protocol == 'aci-v1':
            result.update(aci_binding(report, quote_report_data=reports['TD10']['report_data'],
                                      nonce=nonce, now=now))
        else:
            result.update(legacy_v1_binding(report, quote_report_data=reports['TD10']['report_data'],
                                            nonce=nonce))
    except Rejected as error:
        result['bindingError'] = str(error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    parser.add_argument('--nonce', required=True, help='Original caller-generated nonce, not copied from report')
    parser.add_argument('--binding-protocol', choices=['aci-v1', 'legacy-v1'], default='aci-v1',
                        help='Operator-selected protocol; no fallback based on untrusted report fields')
    args = parser.parse_args()
    try:
        with Path(args.report).open('rb') as stream:
            raw = stream.read(1048577)
        report = strict_json(raw, 1048576)
        result = asyncio.run(diagnose(report, args.nonce, args.binding_protocol))
    except Exception:
        # Provider text and exception details never reach logs.
        result = {'schemaVersion': '1', 'readyForPrivateData': False,
                  'diagnosticError': 'provider_diagnostic_failed'}
    print(json.dumps(result, sort_keys=True))
    # Diagnostic checks can never authorize a live release.
    raise SystemExit(2)


if __name__ == '__main__':
    main()
