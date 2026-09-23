"""Trusted-operator private synthetic holdouts, never a contributor/CI endpoint.

Run only from reviewed controller code. The suite is operator-authored data, not
code supplied in a PR. Neither individual cases nor guest output are returned.
"""
import argparse
import hashlib
import os
import secrets
import stat
import time
from pathlib import Path

from .adapter_check import payment_facts
from .common import canonical, digest, fields, hex_digest, identifier, require, strict_json
from .sandbox import MAX_MODULE, run_adapter


def load_suite(path):
    path = Path(path)
    require(not path.is_symlink(), 'private_suite_permissions')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and
                metadata.st_mode & 0o077 == 0 and metadata.st_size <= 4 * 1024 * 1024,
                'private_suite_permissions')
        suite = strict_json(stream.read(4 * 1024 * 1024 + 1), 4 * 1024 * 1024)
    fields(suite, ('schemaVersion', 'suiteId', 'syntheticOnly', 'cases'))
    require(suite['schemaVersion'] == '1' and suite['syntheticOnly'] is True, 'invalid_private_suite')
    identifier(suite['suiteId'])
    cases = suite['cases']
    require(isinstance(cases, list) and 9 <= len(cases) <= 32, 'invalid_private_suite')
    categories = set()
    for case in cases:
        fields(case, ('category', 'input', 'expected'))
        require(case['category'] in {'positive', 'payer', 'payee', 'amount', 'currency',
                                    'status', 'missing', 'duplicate', 'injection'}, 'invalid_private_suite')
        categories.add(case['category'])
        fields(case['input'], ('evidence', 'transactionId'))
        require(len(canonical(case['input'])) <= 1048576, 'invalid_private_suite')
        require(case['category'] not in ('positive', 'injection') or case['expected'] != 'abstain',
                'invalid_private_suite')
        if case['expected'] != 'abstain':
            fields(case['expected'], ('payer', 'payee', 'amount', 'currency', 'status', 'transaction',
                                      'direction', 'timestamp', 'timestampMeaning', 'capability'))
            require(all(isinstance(v, str) and 0 < len(v) <= 256 for v in case['expected'].values()),
                    'invalid_private_suite')
    require(categories == {'positive', 'payer', 'payee', 'amount', 'currency', 'status',
                           'missing', 'duplicate', 'injection'}, 'incomplete_private_suite')
    return suite


def run_suite(module, artifact_digest, suite_path):
    """The expected artifact digest is selected by the trusted maintainer."""
    hex_digest(artifact_digest)
    require(isinstance(module, bytes) and 0 < len(module) <= MAX_MODULE and
            hashlib.sha256(module).hexdigest() == artifact_digest, 'sandbox_artifact_mismatch')
    suite = load_suite(suite_path)
    passed = True
    for case in suite['cases']:
        try:
            result = run_adapter(module, case['input'], artifact_digest=artifact_digest)
            if case['expected'] == 'abstain':
                ok = isinstance(result, dict) and result.get('outcome') in ('unsupported', 'insufficient_evidence')
            else:
                ok = payment_facts(result) == case['expected']
        except Exception:
            ok = False  # A crash is a failure, not valid abstention.
        passed = passed and ok
    harness = ('holdouts.py', 'adapter_check.py', 'sandbox.py', 'sandbox_worker.py',
               'common.py', 'mercury_oracle.py', 'evaluation.py', 'permits.py', 'requirements.lock', 'requirements-sandbox.lock')
    harness_digest = digest({name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                             for name in harness})
    return {'schemaVersion': '1', 'runId': secrets.token_hex(16), 'suiteId': suite['suiteId'],
            'harnessDigest': harness_digest,
            'artifactDigest': artifact_digest, 'completedAt': int(time.time()),
            'caseCount': len(suite['cases']), 'passed': passed, 'syntheticOnly': True,
            'sourceAuthenticated': False, 'payoutAuthorized': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--suite', required=True)
    parser.add_argument('--artifact', required=True)
    parser.add_argument('--artifact-digest', required=True)
    args = parser.parse_args()
    try:
        with open(args.artifact, 'rb') as stream:
            module = stream.read(MAX_MODULE + 1)
        result = run_suite(module, args.artifact_digest, args.suite)
        print(canonical(result).decode())
        return 0 if result['passed'] else 2
    except Exception:
        print('{"error":"private_holdout_failed"}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
