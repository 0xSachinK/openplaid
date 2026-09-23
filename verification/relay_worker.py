"""Private relay worker; only the parent listener may launch this entrypoint."""
import resource
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from verification.relay import worker

if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    if sys.platform == 'linux':
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    try:
        worker(int(sys.argv[1]))
    except BaseException:
        raise SystemExit(1) from None
