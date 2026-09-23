import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from verification.acquisition_process import fetch_source_isolated
from verification.common import Rejected

ROOT = str(Path(__file__).parents[2])
POLICY = {'enabled': True, 'status': 'approved', 'origins': ['https://example.com'],
          'operations': [{'id': 'synthetic', 'method': 'GET', 'path': '/',
                          'credentialHeaders': ['authorization']}]}


class AcquisitionProcessTests(unittest.TestCase):
    def child(self, setup):
        # Replace only test-child setup; retain real subprocess timeout/pipe behavior.
        original = subprocess.run
        script = ('import sys; sys.path.insert(0, ' + repr(ROOT) + '); ' + setup +
                  '; from verification.acquisition_worker import main; main()')
        def run(command, **kwargs):
            self.assertEqual(kwargs['env'], {})
            self.assertTrue(kwargs['close_fds'])
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertNotIn('synthetic-secret', repr(command))
            return original([sys.executable, '-I', '-c', script], **kwargs)
        return patch('verification.acquisition_process.subprocess.run', side_effect=run)

    def test_blocked_dns_is_killed_at_absolute_deadline(self):
        with self.child('import socket, time; socket.getaddrinfo = lambda *a, **k: time.sleep(60)'), \
                patch('verification.acquisition_process.PROCESS_DEADLINE_SECONDS', 0.5):
            start = time.monotonic()
            with self.assertRaisesRegex(Rejected, '^bank_read_timeout$'):
                fetch_source_isolated(POLICY, {'authorization': 'synthetic-secret'})
            self.assertLess(time.monotonic() - start, 3)

    def test_private_destination_is_rejected_without_returning_session(self):
        with self.child("import socket; socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, '', ('127.0.0.1', 443))]"):
            with self.assertRaisesRegex(Rejected, '^bank_read_failed$'):
                fetch_source_isolated(POLICY, {'authorization': 'synthetic-secret'})

    def test_success_uses_actual_worker_protocol(self):
        with self.child("import verification.acquisition as a; a.fetch_source = lambda p, c: {'synthetic': True}"):
            self.assertEqual(fetch_source_isolated(POLICY, {'authorization': 'synthetic-secret'}),
                             {'synthetic': True})

    def test_unapproved_policy_never_launches_worker(self):
        with patch('verification.acquisition_process.subprocess.run') as run:
            with self.assertRaisesRegex(Rejected, 'source_policy_not_approved'):
                fetch_source_isolated({**POLICY, 'enabled': False}, {})
            run.assert_not_called()

    def test_unexpected_failure_text_is_suppressed(self):
        with self.child("import verification.acquisition as a; a.fetch_source = lambda p, c: (_ for _ in ()).throw(ValueError(c['authorization']))"):
            with self.assertRaisesRegex(Rejected, '^bank_read_failed$'):
                fetch_source_isolated(POLICY, {'authorization': 'synthetic-secret'})
