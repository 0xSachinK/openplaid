"""Absolute process deadline for bank acquisition, including OS DNS and connect.

Select transport only from trusted runtime configuration: direct for integration
testing, nitro for the fixed parent vsock relay. TLS terminates in the child reader.
"""
import subprocess
import sys
from pathlib import Path

from .common import Rejected, canonical, require, strict_json

PROCESS_DEADLINE_SECONDS = 20


def fetch_source_isolated(policy, credentials, *, source_context=None, transport="direct"):
    """policy is trusted operator configuration, never contributor request data.

    Credentials are passed over an anonymous pipe, never environment or argv.
    A killed attempt must retain its controller budget reservation; no auto-retry.
    """
    require(isinstance(policy, dict) and policy.get('enabled') is True and
            policy.get('status') == 'approved', 'source_policy_not_approved')
    require(transport in ('direct', 'nitro'), 'invalid_transport')
    request = canonical({'policy': policy, 'credentials': credentials, 'transport': transport,
                         'sourceContext': source_context})
    require(len(request) <= 65536, 'session_size')
    try:
        result = subprocess.run(
            [sys.executable, '-I', str(Path(__file__).with_name('acquisition_worker.py'))],
            input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={}, close_fds=True, timeout=PROCESS_DEADLINE_SECONDS, check=False)
        require(result.returncode == 0, 'bank_read_failed')
        response = strict_json(result.stdout, 1048576)
        require(isinstance(response, dict) and set(response) == {'ok', 'value'} and
                response['ok'] is True, 'bank_read_failed')
        return response['value']
    except subprocess.TimeoutExpired:
        raise Rejected('bank_read_timeout') from None
    except Rejected:
        raise
    except Exception:
        raise Rejected('bank_read_failed') from None
