import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from verification.common import Rejected
from verification.holdouts import load_suite, run_suite
from verification.mercury_oracle import reference_facts


class HoldoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'private.json'
        fixture = json.loads((Path(__file__).parents[2] /
                              'banks/us/mercury/fixtures/sent.synthetic.json').read_text())
        request = {'evidence': fixture['input'], 'transactionId': fixture['transactionId']}
        expected = reference_facts(fixture['input'], fixture['transactionId'])
        self.suite = {'schemaVersion': '1', 'suiteId': 'synthetic-unit-suite', 'syntheticOnly': True,
                      'cases': [{'category': category, 'input': request,
                                 'expected': expected if category in ('positive', 'injection') else 'abstain'}
                                for category in ('positive', 'payer', 'payee', 'amount', 'currency',
                                                 'status', 'missing', 'duplicate', 'injection')]}
        self.write()

    def tearDown(self):
        self.temp.cleanup()

    def write(self):
        self.path.write_text(json.dumps(self.suite))
        self.path.chmod(0o600)

    def test_reject_world_readable_symlink_and_incomplete_suite(self):
        self.path.chmod(0o644)
        with self.assertRaisesRegex(Rejected, 'private_suite_permissions'):
            load_suite(self.path)
        self.path.chmod(0o600)
        link = self.path.with_name('link.json')
        link.symlink_to(self.path)
        with self.assertRaisesRegex(Rejected, 'private_suite_permissions'):
            load_suite(link)
        self.suite['cases'][-1]['category'] = 'positive'
        self.write()
        with self.assertRaisesRegex(Rejected, 'incomplete_private_suite'):
            load_suite(self.path)

    def test_constant_abstention_fails_and_result_contains_no_cases(self):
        module = b'synthetic-artifact'
        with patch('verification.holdouts.run_adapter', return_value={
                'outcome': 'insufficient_evidence', 'reason': 'private-input'}):
            result = run_suite(module, hashlib.sha256(module).hexdigest(), self.path)
        self.assertFalse(result['passed'])
        self.assertFalse(result['payoutAuthorized'])
        self.assertNotIn('private-input', json.dumps(result))
        self.assertNotIn('cases', result)
        self.assertEqual(result['caseCount'], 9)

    def test_crash_is_not_abstention_and_all_cases_run(self):
        module = b'synthetic-artifact'
        with patch('verification.holdouts.run_adapter', side_effect=RuntimeError('private-input')) as run:
            result = run_suite(module, hashlib.sha256(module).hexdigest(), self.path)
            self.assertEqual(run.call_count, 9)
        self.assertFalse(result['passed'])

    def test_wrong_artifact_never_executes(self):
        with patch('verification.holdouts.run_adapter') as run:
            with self.assertRaisesRegex(Rejected, 'sandbox_artifact_mismatch'):
                run_suite(b'synthetic-artifact', 'a' * 64, self.path)
            run.assert_not_called()
