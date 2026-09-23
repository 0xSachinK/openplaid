"""Normalize informational metadata in an unsigned EIF; never touch measured payloads.

This is a pre-signing build tool, not a verifier or release approver. Source revision
is a build label, not authenticated provenance. Compare PCRs with Nitro CLI afterward.
"""
import json
import re
import struct
import sys
import zlib
from pathlib import Path

if __package__:
    from .inspect_eif import HEADER, MAX_SIZE, inspect_bytes
else:
    from inspect_eif import HEADER, MAX_SIZE, inspect_bytes


def metadata(payload, revision):
    if len(payload) > 65536:
        raise ValueError('eif_metadata_size')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate_metadata_key')
            result[key] = value
        return result
    original = json.loads(payload, object_pairs_hook=unique)
    if not isinstance(original, dict) or set(original) != {
        'ImageName', 'ImageVersion', 'BuildMetadata', 'DockerInfo', 'CustomMetadata'
    }:
        raise ValueError('eif_metadata_schema')
    build = original['BuildMetadata']
    if not isinstance(build, dict) or set(build) != {
        'BuildTime', 'BuildTool', 'BuildToolVersion', 'OperatingSystem', 'KernelVersion'
    } or not all(isinstance(v, str) and len(v) <= 256 for v in build.values()):
        raise ValueError('eif_build_metadata_schema')
    # Keep tool/OS/kernel labels. Volatile timestamps, Docker layer IDs, host paths
    # and tags are deliberately excluded; executable configuration lives in payloads.
    value = {'ImageName': 'openplaid', 'ImageVersion': revision,
        'BuildMetadata': {**build, 'BuildTime': '1970-01-01T00:00:00+00:00'},
        'DockerInfo': {}, 'CustomMetadata': {'sourceCommit': revision,
            'normalization': 'openplaid-unsigned-eif-v1'}}
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def normalize(raw, revision):
    if not isinstance(revision, str) or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('invalid_source_revision')
    before = inspect_bytes(raw)  # Reject signatures, corruption and unknown formats first.
    count = len(before['sections'])
    header = bytearray(raw[:HEADER])
    body = bytearray()
    for index in range(count):
        offset = struct.unpack_from('>Q', raw, 28 + index * 8)[0]
        kind, flags, size = struct.unpack_from('>HHQ', raw, offset)
        payload = raw[offset + 12:offset + 12 + size]
        if kind == 5:
            payload = metadata(payload, revision)
        struct.pack_into('>Q', header, 28 + index * 8, HEADER + len(body))
        struct.pack_into('>Q', header, 284 + index * 8, len(payload))
        body.extend(struct.pack('>HHQ', kind, flags, len(payload)))
        body.extend(payload)
    result = header + body
    struct.pack_into('>I', result, 544, zlib.crc32(result[548:], zlib.crc32(result[:544])))
    after = inspect_bytes(result)
    measured = lambda report: [s for s in report['sections'] if s['type'] != 'metadata']
    if measured(before) != measured(after):
        raise ValueError('eif_payload_changed')
    return bytes(result)


if __name__ == '__main__':
    with Path(sys.argv[1]).open('rb') as stream:
        source = stream.read(MAX_SIZE + 1)
    result = normalize(source, sys.argv[3])
    # New output only; never replace input or overwrite a signed/reviewed artifact.
    with Path(sys.argv[2]).open('xb') as stream:
        stream.write(result)
