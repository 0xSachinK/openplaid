"""Private enclave acquisition/comparison stage; no public route or receipt authority.

Trust arguments come from the measured runtime, never submission-selected values.
Only a consumed encrypted owner session can supply credentials and transaction
selection. No caller document, URL, request body or model prompt is accepted.
"""
import hashlib

from .acquisition_process import fetch_source_isolated
from .adapter_check import check_adapter
from .common import fields, identifier, require
from .mercury_oracle import CAPABILITY
from .sandbox import MAX_MODULE


def acquire_and_compare(channel, module, envelope, permit, *, operator_public_key,
                        policy_digest, source_policy):
    """Return a PRIVATE oracle projection for a later independently trusted model stage.

    This never emits a verified result or signs a receipt. Callers must not expose the
    projection to the parent/controller or logs. Failures consume an authorized session
    and preserve its spending reservation; the function never retries bank acquisition.
    """
    require(isinstance(source_policy, dict) and source_policy.get('enabled') is True and
            source_policy.get('status') == 'approved', 'source_policy_not_approved')
    require(source_policy.get('capability') == CAPABILITY, 'unsupported_capability')
    require(isinstance(module, bytes) and 0 < len(module) <= MAX_MODULE, 'sandbox_module_size')
    artifact_digest = hashlib.sha256(module).hexdigest()
    session = channel.decrypt_authorized(envelope, permit,
        operator_public_key=operator_public_key, policy_digest=policy_digest,
        artifact_digest=artifact_digest)
    fields(session, ('credentials', 'sourceContext', 'transactionId'))
    identifier(session['transactionId'])
    # The absolute-deadline worker performs TLS inside the enclave; the parent
    # can relay only encrypted bytes to the configured bank destination.
    document = fetch_source_isolated(source_policy, session['credentials'],
        source_context=session['sourceContext'], transport='nitro')
    result = check_adapter(module, document, session['transactionId'], permit=permit,
        operator_public_key=operator_public_key,
        enclave_key_digest=hashlib.sha256(channel.public_key_der).hexdigest(),
        policy_digest=policy_digest, challenge=envelope['context']['nonce'])
    # Deliberately retain 'consistent', not 'verified'. The adapter still cannot
    # claim authenticity; this provenance originates solely in the acquisition path.
    if result['outcome'] == 'consistent':
        return {**result, 'sourceAuthenticated': True}
    return result
