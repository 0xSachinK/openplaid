import copy
import json
import unittest
from unittest.mock import Mock, patch

from verification.acquisition import fetch_source, request_plan
from verification.common import Rejected

OPERATION = {'id': 'mercury-history-v1', 'method': 'POST',
             'path': '/organizations/{organizationId}/transactions-lite',
             'credentialHeaders': ['cookie', 'x-csrf-protect']}
CONTEXT = {'organizationId': '00000000-0000-4000-8000-000000000001'}
POLICY = {'enabled': True, 'status': 'approved', 'origins': ['https://backend.mercury.com'],
          'operations': [OPERATION]}
CREDENTIALS = {'cookie': '_SESSION=synthetic', 'x-csrf-protect': 'synthetic'}


class MercuryAcquisitionTests(unittest.TestCase):
    def test_only_reviewed_history_post_is_allowed(self):
        for change in ({'id': 'send-payment'}, {'method': 'PUT'},
                       {'path': '/organizations/{organizationId}/send'},
                       {'path': '/organizations/{organizationId}/transactions-lite?redirect=other'},
                       {'body': {'anything': True}}):
            with self.subTest(change=change), self.assertRaises(Rejected):
                request_plan('backend.mercury.com', {**OPERATION, **change}, CONTEXT)
        with self.assertRaisesRegex(Rejected, 'operation_forbidden'):
            request_plan('attacker.mercury.com', OPERATION, CONTEXT)

    def test_untrusted_selectors_cannot_change_request_shape(self):
        for context in (None, {}, {'organizationId': '../send'},
                        {'organizationId': CONTEXT['organizationId'] + '?x=1'},
                        {'organizationId': CONTEXT['organizationId'], 'limit': 10000},
                        {'organizationId': CONTEXT['organizationId'], 'url': 'https://other.example'},
                        {'organizationId': CONTEXT['organizationId'], 'body': {}}):
            with self.subTest(context=context), self.assertRaises(Rejected):
                request_plan('backend.mercury.com', OPERATION, context)

    def test_fixed_post_reaches_http_client_without_credential_body(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.side_effect = lambda key, default=None: {
            'Content-Encoding': 'identity', 'Content-Type': 'application/json'}.get(key, default)
        response.read.return_value = b'{"data":{"transactions":[],"parties":[]}}'
        with patch('verification.acquisition.http.client.HTTPSConnection', return_value=connection), \
             patch('verification.acquisition.ReadDeadline'):
            fetch_source(POLICY, CREDENTIALS, source_context=CONTEXT, socket_factory=Mock())
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ('POST', '/organizations/' + CONTEXT['organizationId'] + '/transactions-lite'))
        self.assertEqual(json.loads(kwargs['body']), {'limit': 100, 'cursorDirection': 'startAfter',
            'sortSettings': {'primary': {'tag': 'date', 'contents': 'desc'}}, 'timezone': 'UTC'})
        self.assertNotIn(b'synthetic', kwargs['body'])
        self.assertEqual(kwargs['headers']['Content-Type'], 'application/json')
        self.assertEqual(kwargs['headers']['cookie'], CREDENTIALS['cookie'])

    def test_unapproved_policy_and_header_overrides_fail_before_connection(self):
        for name in ('content-type', 'content-length', 'host', 'transfer-encoding'):
            policy = copy.deepcopy(POLICY)
            policy['operations'][0]['credentialHeaders'] = [name]
            with patch('verification.acquisition.http.client.HTTPSConnection') as connection:
                with self.assertRaisesRegex(Rejected, 'invalid_credential_policy'):
                    fetch_source(policy, {name: 'synthetic'}, source_context=CONTEXT)
                connection.assert_not_called()
        with patch('verification.acquisition.http.client.HTTPSConnection') as connection:
            with self.assertRaisesRegex(Rejected, 'source_policy_not_approved'):
                fetch_source({**POLICY, 'enabled': False}, CREDENTIALS, source_context=CONTEXT)
            connection.assert_not_called()
