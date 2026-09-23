"""Admission-bound deterministic stage before any paid model evaluation.

Internal enclave component, not a public endpoint. The caller must consume the
one-use session challenge and authenticate acquisition before invoking this stage.
No result here establishes source authenticity, authorizes a receipt or pays funds.
"""
import hashlib

from .common import fields, require
from .mercury_oracle import CAPABILITY, evidence_candidates
from .permits import verify
from .sandbox import MAX_MODULE, run_adapter


def payment_facts(result):
    """Validate the untrusted adapter contract and discard all free-form output."""
    fields(result, ('outcome', 'payment'))
    require(result['outcome'] == 'supported', 'adapter_abstained')
    payment = result['payment']
    fields(payment, ('schemaVersion', 'provider', 'transactionId', 'payer', 'payee',
                     'amountMinor', 'currency', 'direction', 'status', 'timestamp',
                     'timestampMeaning', 'sourceAuthenticated', 'limitations'))
    require(payment['schemaVersion'] == '1' and payment['provider'] == 'us/mercury' and
            payment['sourceAuthenticated'] is False, 'adapter_contract')
    for role, scheme, provenance in (
        ('payer', 'mercury-party-id', 'transaction.primaryPartyId'),
        ('payee', 'us-routing-account', 'transaction.details.domesticWireRoutingInfo'),
    ):
        fields(payment[role], ('id', 'scheme', 'provenance'))
        require(payment[role]['scheme'] == scheme and payment[role]['provenance'] == provenance,
                'adapter_contract')
    limitations = payment['limitations']
    require(isinstance(limitations, list) and len(limitations) <= 16 and
            all(isinstance(v, str) and len(v) <= 512 for v in limitations), 'adapter_contract')
    facts = {'payer': payment['payer']['id'], 'payee': payment['payee']['id'],
             'amount': payment['amountMinor'], 'currency': payment['currency'],
             'status': payment['status'], 'transaction': payment['transactionId'],
             'direction': payment['direction'], 'timestamp': payment['timestamp'],
             'timestampMeaning': payment['timestampMeaning'], 'capability': CAPABILITY}
    require(all(isinstance(v, str) and 0 < len(v) <= 256 for v in facts.values()), 'adapter_contract')
    return facts


def check_adapter(module, document, selected_transaction, *, permit, operator_public_key,
                  enclave_key_digest, policy_digest, challenge):
    """Verify controller authority before oracle work or contributor execution.

    The public key and binding values are trusted runtime configuration/context,
    never request-selected. Return private oracle projections only on exact agreement.
    The caller must not publish these values or send them to an unapproved model.
    """
    require(isinstance(module, bytes) and 0 < len(module) <= MAX_MODULE, 'sandbox_module_size')
    artifact_digest = hashlib.sha256(module).hexdigest()
    claims = verify(permit, operator_public_key, enclave_key_digest=enclave_key_digest,
                    policy_digest=policy_digest, artifact_digest=artifact_digest, challenge=challenge)
    expected, candidates = evidence_candidates(document, selected_transaction)
    result = run_adapter(module, {'evidence': document, 'transactionId': selected_transaction},
                         artifact_digest=claims['artifactDigest'])
    require(isinstance(result, dict), 'adapter_contract')
    if result.get('outcome') in ('insufficient_evidence', 'unsupported'):
        # Free-form reasons may contain evidence or instructions; never forward them.
        return {'outcome': 'needs_review', 'code': 'adapter_abstained'}
    facts = payment_facts(result)
    if facts != expected:
        return {'outcome': 'contradicted', 'code': 'field_mismatch'}
    return {'outcome': 'consistent', 'code': 'adapter_oracle_agreement',
            'facts': expected, 'candidates': candidates, 'sourceAuthenticated': False}
