"""Run an admitted Wasm artifact in a fresh bounded worker; never log guest output."""
import hashlib
import subprocess
import sys
from pathlib import Path

from .common import Rejected, b64, canonical, hex_digest, require, strict_json

MAX_MODULE = 2 * 1024 * 1024
MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 8192


def run_adapter(module, input_value, *, artifact_digest):
    """artifact_digest must come from trusted admission, not the submitted module.

    The input is a credential-free evidence projection. Wasm only receives those
    bytes; no inherited descriptors, environment, filesystem or network capabilities.
    The result is still untrusted and must be compared to the independent oracle.
    """
    hex_digest(artifact_digest)
    require(isinstance(module, bytes) and 0 < len(module) <= MAX_MODULE, 'sandbox_module_size')
    require(hashlib.sha256(module).hexdigest() == artifact_digest, 'sandbox_artifact_mismatch')
    encoded = canonical(input_value)
    require(len(encoded) <= MAX_INPUT, 'sandbox_input_size')
    request = canonical({'module': b64(module), 'input': b64(encoded)})
    try:
        result = subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('sandbox_worker.py'))],
                                input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={}, close_fds=True, timeout=10, check=False)
        require(result.returncode == 0, 'sandbox_failed')
        response = strict_json(result.stdout, MAX_OUTPUT + 1024)
        require(isinstance(response, dict) and response.get('ok') is True and
                set(response) == {'ok', 'value'}, 'sandbox_failed')
        return response['value']
    except Rejected:
        raise
    except Exception as error:
        raise Rejected('sandbox_failed') from error
