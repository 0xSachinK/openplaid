"""Disposable credential-free hardware test image entrypoint, never a live verifier.

The production Dockerfile never selects this entrypoint. No bank policy is enabled.
Only cached synthetic test results and ordinary Nitro attestations are exposed.
"""
import hashlib
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from verification import runtime
from verification.adapter_check import payment_facts
from verification.common import fields
from verification.mercury_oracle import reference_facts
from verification.sandbox import run_adapter


def probe():
    suite = unittest.defaultTestLoader.loadTestsFromNames([
        'verification.tests.test_sandbox', 'verification.tests.test_authorized_channel',
        'verification.tests.test_relay'])
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    root = Path(__file__).resolve().parents[2]
    fixture = json.loads((root / 'banks/us/mercury/fixtures/sent.synthetic.json').read_text())
    module = (Path(__file__).parent / 'lab-assets/mercury.wasm').read_bytes()
    artifact_digest = hashlib.sha256(module).hexdigest()
    checks = 0
    expected = reference_facts(fixture['input'], fixture['transactionId'])
    actual = run_adapter(module, {'evidence': fixture['input'], 'transactionId': fixture['transactionId']},
                         artifact_digest=artifact_digest)
    if payment_facts(actual) != expected:
        raise ValueError('synthetic_adapter_mismatch')
    checks += 1
    for status in ('pending', 'failed', 'returned'):
        document = json.loads(json.dumps(fixture['input']))
        document['data']['transactions'][0]['status'] = status
        actual = run_adapter(module, {'evidence': document, 'transactionId': fixture['transactionId']},
                             artifact_digest=artifact_digest)
        if actual.get('outcome') != 'insufficient_evidence':
            raise ValueError('synthetic_adapter_mismatch')
        checks += 1
    return {'hardwareComponentTestsPassed': result.wasSuccessful(), 'unitCases': result.testsRun,
            'realAdapterCases': checks, 'artifactDigest': artifact_digest,
            'realVsockEgressTested': False, 'sourceAuthenticated': False,
            'liveVerification': False, 'independentRebuildVerified': False}


class ProbeRuntime(runtime.Runtime):
    def __init__(self):
        super().__init__()
        try:
            self.report = probe()
        except Exception:
            self.report = {'hardwareComponentTestsPassed': False, 'error': 'hardware_probe_failed',
                           'liveVerification': False}

    def handle(self, request):
        if isinstance(request, dict) and request.get('operation') == 'hardware-smoke':
            fields(request, ('operation',))
            return self.report
        return super().handle(request)


if __name__ == '__main__':
    runtime.Runtime = ProbeRuntime
    runtime.main()
