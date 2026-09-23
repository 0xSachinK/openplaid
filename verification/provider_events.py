"""Bounded dstack RTMR3 diagnostics; measurement consistency is not approval."""
import hashlib

from .common import require, strict_json

RUNTIME_EVENT = 0x08000001


def measured_configuration(evidence, *, quote_rtmr3):
    """Use only RTMR3 from independently verified Intel quote claims.

    Recompute runtime-event digests from their semantic fields; trusting an
    adjacent digest would allow a substituted event name or payload. This checks
    measurement consistency only, never code provenance or platform acceptance.
    """
    def unhex(value, size=None):
        require(isinstance(value, str) and len(value) <= 131072 and
                len(value) % 2 == 0 and all(c in '0123456789abcdef' for c in value),
                'provider_event_encoding')
        decoded = bytes.fromhex(value)
        require(size is None or len(decoded) == size, 'provider_event_encoding')
        return decoded

    require(isinstance(evidence, dict), 'provider_event_log')
    raw = evidence.get('event_log')
    require(isinstance(raw, str), 'provider_event_log')
    events = strict_json(raw.encode(), 262144)
    require(isinstance(events, list) and 1 <= len(events) <= 256, 'provider_event_log')
    expected = unhex(quote_rtmr3, 48)
    register = bytes(48)
    measured = {}
    ready = False
    for event in events:
        require(isinstance(event, dict) and set(event) ==
                {'imr', 'event_type', 'digest', 'event', 'event_payload'}, 'provider_event_log')
        require(type(event['imr']) is int and 0 <= event['imr'] <= 3 and
                type(event['event_type']) is int and 0 <= event['event_type'] < 2**32,
                'provider_event_log')
        if event['imr'] != 3:
            continue
        # This diagnostic supports only the measured dstack runtime event format.
        require(event['event_type'] == RUNTIME_EVENT, 'provider_event_type')
        name = event['event']
        require(isinstance(name, str) and name.isascii() and 0 < len(name) <= 128,
                'provider_event_log')
        payload = unhex(event['event_payload'])
        digest = hashlib.sha384(RUNTIME_EVENT.to_bytes(4, 'little') + b':' +
                                name.encode() + b':' + payload).digest()
        require(unhex(event['digest'], 48) == digest, 'provider_event_digest')
        register = hashlib.sha384(register + digest).digest()
        if name == 'system-ready':
            require(not ready and not payload, 'provider_event_boundary')
            ready = True
        elif name in ('app-id', 'compose-hash'):
            require(not ready and name not in measured, 'provider_event_identity')
            measured[name] = payload
    require(register == expected, 'provider_event_quote_mismatch')
    require(ready and set(measured) == {'app-id', 'compose-hash'} and
            len(measured['app-id']) == 20 and len(measured['compose-hash']) == 32,
            'provider_event_identity')
    compose = evidence.get('app_compose')
    require(isinstance(compose, str) and len(compose.encode()) <= 131072,
            'provider_compose_size')
    require(hashlib.sha256(compose.encode()).digest() == measured['compose-hash'],
            'provider_compose_mismatch')
    return {'eventLogQuoteBound': True, 'composeQuoteBound': True,
            'measuredAppId': measured['app-id'].hex(),
            'measuredComposeSha256': measured['compose-hash'].hex(),
            'workloadIdentityApproved': False, 'readyForPrivateData': False}
