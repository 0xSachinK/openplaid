import tempfile
import time
import unittest
from pathlib import Path

from verification.common import Rejected
from verification.control import Ledger


class OperatorInspectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ledger = Ledger(Path(self.directory.name) / 'ledger')
        self.addCleanup(self.ledger.db.close)
        self.ticket = self.ledger.create_ticket(award='synthetic', contributor='example',
            revision='a' * 64, capability='synthetic/bank', expires=int(time.time()) + 300)['id']

    def test_inspection_does_not_mutate_and_versions_still_gate_judgment(self):
        before = self.ledger.db.total_changes
        snapshot = self.ledger.inspect_ticket(self.ticket)
        self.assertEqual(self.ledger.db.total_changes, before)
        self.assertEqual(snapshot['attempts'], [])
        self.ledger.judge(self.ticket, actor='operator', version=0, decision='admit', evidence_digest='b'*64)
        with self.assertRaisesRegex(Rejected, 'stale_judgment'):
            self.ledger.judge(self.ticket, actor='operator', version=snapshot['ticket']['version'],
                              decision='revoke', evidence_digest='b'*64)
        current = self.ledger.inspect_ticket(self.ticket)
        self.assertEqual(current['ticket']['version'], 1)
        self.assertEqual(current['judgments'][0]['evidence_digest'], 'b'*64)
        self.assertFalse(current['payoutEnabled'])

    def test_sequence_pages_include_new_events_without_duplicates(self):
        first = self.ledger.audit_events(limit=1)
        self.assertEqual(len(first['events']), 1)
        self.ledger.judge(self.ticket, actor='operator', version=0, decision='admit', evidence_digest='b'*64)
        self.ledger.pause()
        second = self.ledger.audit_events(first['nextAfter'], 1)
        self.assertTrue(second['hasMore'])
        third = self.ledger.audit_events(second['nextAfter'], 1)
        self.assertFalse(third['hasMore'])
        self.assertEqual([p['events'][0]['kind'] for p in (first, second, third)],
                         ['ticket_created', 'judgment', 'paused'])
        self.assertEqual(second['events'][0]['payload']['actor'], 'operator')
        empty = self.ledger.audit_events(third['nextAfter'], 1)
        self.assertEqual(empty['events'], [])
        self.assertEqual(empty['nextAfter'], third['nextAfter'])

    def test_page_bounds_and_unknown_ticket(self):
        for after, limit in ((-1, 1), (2**63, 1), (True, 1), (0, 101), (0, 0)):
            with self.assertRaisesRegex(Rejected, 'invalid_audit_page'):
                self.ledger.audit_events(after, limit)
        with self.assertRaisesRegex(Rejected, 'unknown_ticket'):
            self.ledger.inspect_ticket('missing')
