"""Read-only inspection of unsigned x86_64 EIF v4 build artifacts.

Format reference: aws/aws-nitro-enclaves-image-format, src/defs/mod.rs.
No parsing or rewriting of executable payloads, no signature validation claim.
"""
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

HEADER = 548
MAX_SIZE = 512 * 1024 * 1024
TYPES = {1: 'kernel', 2: 'cmdline', 3: 'ramdisk', 5: 'metadata'}


def inspect(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_SIZE + 1)
    if not HEADER <= len(raw) <= MAX_SIZE:
        raise ValueError('eif_size')
    magic, version, flags, memory, cpus, reserved, count = struct.unpack('>4sHHQQHH', raw[:28])
    if magic != b'.eif' or version != 4 or flags != 0 or reserved != 0 or not 1 <= count <= 32:
        raise ValueError('eif_header')
    offsets = struct.unpack('>32Q', raw[28:284])
    sizes = struct.unpack('>32Q', raw[284:540])
    unused, expected_crc = struct.unpack('>II', raw[540:548])
    if unused or any(offsets[count:]) or any(sizes[count:]):
        raise ValueError('eif_header')
    crc = zlib.crc32(raw[548:], zlib.crc32(raw[:544]))
    if crc != expected_crc:
        raise ValueError('eif_crc')
    sections = []
    end = HEADER
    for offset, size in zip(offsets[:count], sizes[:count]):
        if offset != end or offset + 12 + size > len(raw):
            raise ValueError('eif_section_bounds')
        kind, section_flags, section_size = struct.unpack('>HHQ', raw[offset:offset+12])
        if kind == 4:
            raise ValueError('signed_eif_not_supported')
        if kind not in TYPES or section_flags != 0 or section_size != size:
            raise ValueError('eif_section_header')
        end = offset + 12 + size
        payload = memoryview(raw)[offset+12:end]
        sections.append({'type': TYPES[kind], 'size': size,
                         'sha384': hashlib.sha384(payload).hexdigest()})
    if end != len(raw):
        raise ValueError('eif_trailing_bytes')
    kinds = [s['type'] for s in sections]
    if kinds.count('kernel') != 1 or kinds.count('cmdline') != 1 or kinds.count('metadata') != 1 or kinds.count('ramdisk') < 1:
        raise ValueError('eif_section_set')
    return {'format': 4, 'architecture': 'x86_64', 'defaultMemory': memory,
            'defaultCpus': cpus, 'crcVerified': True, 'signed': False, 'sections': sections}


if __name__ == '__main__':
    print(json.dumps(inspect(sys.argv[1]), sort_keys=True))
