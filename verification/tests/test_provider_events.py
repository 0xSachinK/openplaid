import copy
import hashlib
import json
import unittest

from verification.common import Rejected
from verification.provider_events import RUNTIME_EVENT, measured_configuration


def fixture(items=None):
    compose = '{"synthetic":true}'
    items = items or [('app-id', b'a' * 20),
                      ('compose-hash', hashlib.sha256(compose.encode()).digest()),
                      ('system-ready', b'')]
    events = []
    register = bytes(48)
    for name, payload in items:
        digest = hashlib.sha384(b'\x01\x00\x00\x08:' + name.encode() + b':' + payload).digest()
        register = hashlib.sha384(register + digest).digest()
        events.append({'imr': 3, 'event_type': RUNTIME_EVENT, 'event': name,
                       'event_payload': payload.hex(), 'digest': digest.hex()})
    return {'event_log': json.dumps(events), 'app_compose': compose}, register.hex()


class ProviderEventsTests(unittest.TestCase):
    def test_bound_measurements_never_approve_workload(self):
        evidence, register = fixture()
        result = measured_configuration(evidence, quote_rtmr3=register)
        self.assertTrue(result['composeQuoteBound'])
        self.assertFalse(result['workloadIdentityApproved'])
        self.assertFalse(result['readyForPrivateData'])

    def test_substitution_quote_mismatch_and_compose_mutation(self):
        evidence, register = fixture()
        for field in ('event', 'event_payload', 'digest'):
            altered = copy.deepcopy(evidence)
            events = json.loads(altered['event_log'])
            events[0][field] = {'event': 'forged', 'event_payload': 'bb' * 20,
                                'digest': 'cc' * 48}[field]
            altered['event_log'] = json.dumps(events)
            with self.assertRaises(Rejected):
                measured_configuration(altered, quote_rtmr3=register)
        with self.assertRaises(Rejected):
            measured_configuration(evidence, quote_rtmr3='ff' * 48)
        evidence['app_compose'] += ' '
        with self.assertRaises(Rejected):
            measured_configuration(evidence, quote_rtmr3=register)

    def test_duplicate_and_post_ready_identity_rejected_even_when_measured(self):
        app = ('app-id', b'a' * 20)
        compose = ('compose-hash', hashlib.sha256(b'{"synthetic":true}').digest())
        ready = ('system-ready', b'')
        for items in ([app, app, compose, ready], [compose, ready, app],
                      [app, compose], [app, compose, ready, ready]):
            evidence, register = fixture(items)
            with self.assertRaises(Rejected):
                measured_configuration(evidence, quote_rtmr3=register)

    def test_bounded_and_unknown_inputs(self):
        evidence, register = fixture()
        for raw in ('[]', '[{}]' , '[' * 262145):
            with self.assertRaises(Rejected):
                measured_configuration(dict(evidence, event_log=raw), quote_rtmr3=register)
        events = json.loads(evidence['event_log'])
        events[0]['event_type'] = 1
        with self.assertRaises(Rejected):
            measured_configuration(dict(evidence, event_log=json.dumps(events)), quote_rtmr3=register)
