"""Credential-free smoke of the real compiled Mercury parser; no live proof claim."""
import copy
import hashlib
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root))
from verification.sandbox import run_adapter

fixture = json.loads((root / 'banks/us/mercury/fixtures/sent.synthetic.json').read_text())
module = (root / '.local/verification/mercury.wasm').read_bytes()
manifest = json.loads((root / '.local/verification/mercury-wasm-build.json').read_text())
digest = manifest['artifactSha256']
assert hashlib.sha256(module).hexdigest() == digest

def run(evidence):
    return run_adapter(module, {'evidence': evidence, 'transactionId': fixture['transactionId']},
                       artifact_digest=digest)

result = run(fixture['input'])
expected = fixture['expected']
assert result['outcome'] == expected['outcome'] == 'supported'
payment = result['payment']
assert all(payment[k] == expected[k] for k in ('amountMinor', 'currency', 'status', 'timestamp'))
assert payment['payer']['id'] == expected['payerId'] and payment['payee']['id'] == expected['payeeId']
assert payment['sourceAuthenticated'] is False
for status in ('pending', 'failed', 'returned'):
    document = copy.deepcopy(fixture['input'])
    document['data']['transactions'][0]['status'] = status
    assert run(document)['outcome'] == 'insufficient_evidence'
document = copy.deepcopy(fixture['input'])
document['data']['transactions'].append(document['data']['transactions'][0])
assert run(document)['outcome'] == 'insufficient_evidence'
print(json.dumps({'sandboxMercurySmokePassed': True, 'cases': 5,
                  'artifactSha256': digest, 'sourceAuthenticated': False}))

# Synthetic controller permit exercises the real parser-to-oracle integration.
# This key has no deployed authority; no bank authentication or model call occurs.
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from verification.adapter_check import check_adapter
from verification.permits import issue

controller = Ed25519PrivateKey.generate()
permit = issue({'audience': 'openplaid-verification-v1', 'attempt': 'synthetic-attempt',
                'ticket': 'synthetic-ticket', 'artifactDigest': digest,
                'policyDigest': 'a' * 64, 'enclaveKeyDigest': 'b' * 64, 'challenge': 'c' * 64,
                'expiresAt': int(time.time()) + 60, 'maximumMicroUsd': 1}, controller)
checked = check_adapter(module, fixture['input'], fixture['transactionId'], permit=permit,
                        operator_public_key=controller.public_key().public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                        enclave_key_digest='b' * 64, policy_digest='a' * 64, challenge='c' * 64)
assert checked['outcome'] == 'consistent' and checked['facts']['amount'] == '12345'
assert checked['sourceAuthenticated'] is False
print(json.dumps({'adapterOracleIntegrationPassed': True, 'syntheticPermit': True,
                  'sourceAuthenticated': False, 'paidInference': False}))
