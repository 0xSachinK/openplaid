import importlib.util
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

spec = importlib.util.spec_from_file_location('inspect_eif', Path(__file__).parents[1] / 'infra/inspect_eif.py')
eif = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eif)


def fixture(sections=None):
    sections = sections or [(1,b'kernel'),(2,b'command'),(3,b'ramdisk'),(5,b'{}')]
    header = bytearray(548)
    struct.pack_into('>4sHHQQHH', header, 0, b'.eif',4,0,1024,2,0,len(sections))
    body = bytearray()
    for i, (kind, payload) in enumerate(sections):
        struct.pack_into('>Q', header, 28+8*i, 548+len(body))
        struct.pack_into('>Q', header, 284+8*i, len(payload))
        body += struct.pack('>HHQ', kind,0,len(payload))+payload
    raw = header+body
    struct.pack_into('>I', raw, 544,zlib.crc32(raw[548:],zlib.crc32(raw[:544])))
    return raw


class EifInspectionTests(unittest.TestCase):
    def inspect(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'synthetic.eif'
            path.write_bytes(raw)
            return eif.inspect(path)

    def test_payload_changes_are_distinguished_from_metadata(self):
        a=self.inspect(fixture())
        b=self.inspect(fixture([(1,b'kernel'),(2,b'command'),(3,b'ramdisk'),(5,b'{"time":1}')]))
        self.assertTrue(a['crcVerified'])
        self.assertEqual(a['sections'][:3],b['sections'][:3])
        self.assertNotEqual(a['sections'][3],b['sections'][3])

    def test_crc_truncation_trailing_bytes_and_signed_images_rejected(self):
        modified=fixture(); modified[-1]^=1
        cases=[modified,fixture()[:-1],fixture()+b'extra',fixture([(1,b'a'),(2,b'b'),(3,b'c'),(4,b'signed'),(5,b'{}')])]
        for raw in cases:
            with self.assertRaises(ValueError): self.inspect(raw)

    def test_overlapping_sections_fail_even_with_valid_crc(self):
        raw=fixture();struct.pack_into('>Q',raw,36,548)
        struct.pack_into('>I',raw,544,zlib.crc32(raw[548:],zlib.crc32(raw[:544])))
        with self.assertRaisesRegex(ValueError,'eif_section_bounds'):self.inspect(raw)
