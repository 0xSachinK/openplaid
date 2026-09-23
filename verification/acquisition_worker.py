"""Private bank reader process. Session credentials arrive only through stdin."""
import resource
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verification.acquisition import fetch_source
from verification.common import canonical, fields, require, strict_json


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    if sys.platform == 'linux':
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    try:
        request = strict_json(sys.stdin.buffer.read(65537), 65536)
        fields(request, ('policy', 'credentials'))
        value = fetch_source(request['policy'], request['credentials'])
        body = canonical({'ok': True, 'value': value})
        require(len(body) <= 1048576, 'bank_response_size')
        sys.stdout.buffer.write(body)
    except BaseException:
        # Neither response data nor credential-bearing exception text may escape.
        sys.stdout.buffer.write(b'{"ok":false}')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
