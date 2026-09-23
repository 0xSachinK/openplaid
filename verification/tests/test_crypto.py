import copy
import datetime
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from verification.attestation import verify_document
from verification.channel import SessionChannel
from verification.client import verified_session
from verification.common import Rejected, b64, canonical
from verification.venice import decode_stream, decrypt_chunk, encrypt_message, public_bytes, request_body


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.leaf_key = ec.generate_private_key(ec.SECP384R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test root")])
        self.root = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
                     .public_key(self.root_key.public_key()).serial_number(1)
                     .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                     .sign(self.root_key, hashes.SHA384()))
        self.leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic NSM")]))
                     .issuer_name(issuer).public_key(self.leaf_key.public_key()).serial_number(2)
                     .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1))
                     .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                     .sign(self.root_key, hashes.SHA384()))
        self.release = {"status": "approved", "expiresAt": time.time()+300,
                        "policyDigest": "b" * 64, "measurements": {str(k): "a" * 96 for k in (0,1,2,8)}}
        self.doc = {"digest": "SHA384", "timestamp": int(time.time()*1000), "nonce": b"n" * 32,
                    "public_key": b"synthetic-test-key", "user_data": bytes.fromhex("b"*64),
                    "pcrs": {k: bytes.fromhex("a"*96) for k in (0,1,2,8)},
                    "certificate": self.leaf.public_bytes(serialization.Encoding.DER),
                    "cabundle": [self.root.public_bytes(serialization.Encoding.DER)]}
        path = Path(self.directory.name) / "public-root"
        path.write_bytes(self.root.public_bytes(serialization.Encoding.PEM))
        self.patches = [patch("verification.attestation.ROOT", path),
                        patch("verification.attestation.ROOT_SHA256", self.root.fingerprint(hashes.SHA256()).hex())]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.directory.cleanup()

    def encode(self, doc):
        protected = cbor2.dumps({1: -35})
        payload = cbor2.dumps(doc)
        signed = cbor2.dumps(["Signature1", protected, b"", payload])
        r,s = decode_dss_signature(self.leaf_key.sign(signed, ec.ECDSA(hashes.SHA384())))
        return cbor2.dumps([protected, {}, payload, r.to_bytes(48,"big")+s.to_bytes(48,"big")])

    def verify(self, raw):
        return verify_document(raw, nonce=b"n"*32, public_key_der=b"synthetic-test-key", release=self.release)

    def test_valid_chain_and_cose_signature(self):
        self.assertTrue(self.verify(self.encode(self.doc))["verified"])

    def test_wrong_nonce_key_policy_pcr_and_stale_time(self):
        cases = [("nonce", b"x"*32), ("public_key", b"other"), ("user_data", b"x"*32),
                 ("timestamp", 0), ("pcrs", {k:b"\0"*48 for k in (0,1,2,8)})]
        for field, value in cases:
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify(self.encode({**self.doc, field: value}))

    def test_tampered_cose_fails(self):
        raw = bytearray(self.encode(self.doc)); raw[-1] ^= 1
        with self.assertRaises(Rejected):
            self.verify(bytes(raw))

    def test_unrelated_certificate_and_trailing_data_fail(self):
        with self.assertRaises(Rejected):
            self.verify(self.encode({**self.doc, "certificate": self.root.public_bytes(serialization.Encoding.DER)}))
        with self.assertRaises(Rejected):
            self.verify(self.encode(self.doc)+b"extra")

    def test_secret_sharing_requires_real_quote_consent_and_live_release(self):
        channel = SessionChannel()
        context = channel.challenge("attempt-1", "c" * 64)
        release = {**self.release, "liveVerification": True}
        doc = {**self.doc, "public_key": channel.public_key_der}
        response = {"attestation": b64(self.encode(doc)), "publicKey": b64(channel.public_key_der),
                    "policyDigest": release["policyDigest"]}
        args = dict(nonce=b"n" * 32, release=release, context=context,
                    attempt="attempt-1", binding_digest="c" * 64,
                    session={"synthetic": "example"}, consent=True)
        for changes in ({"consent": False}, {"release": self.release},
                        {"nonce": b"x" * 32}, {"attempt": "wrong"},
                        {"binding_digest": "d" * 64}):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                verified_session(response, **{**args, **changes})
        envelope = verified_session(response, **args)
        self.assertEqual(channel.decrypt_once(envelope), {"synthetic": "example"})


class VeniceTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256K1())

    def test_roundtrip_and_tampering(self):
        ciphertext = encrypt_message("synthetic only", public_bytes(self.key))
        self.assertEqual(decrypt_chunk(ciphertext, self.key), "synthetic only")
        raw = bytearray.fromhex(ciphertext); raw[-1] ^= 1
        with self.assertRaises(Rejected):
            decrypt_chunk(raw.hex(), self.key)
        with self.assertRaises(Rejected):
            decrypt_chunk("plain text fallback", self.key)

    def test_stream_completeness_and_replay(self):
        ciphertext = encrypt_message('{"decision":"ambiguous"}', public_bytes(self.key))
        event = b"data: "+canonical({"choices":[{"index":0,"delta":{"content":ciphertext}}]})
        self.assertEqual(decode_stream([event,b"data: [DONE]"], self.key), '{"decision":"ambiguous"}')
        for events in ([event], [event,event,b"data: [DONE]"], [b"data: [DONE]"]):
            with self.assertRaises(Rejected):
                decode_stream(events, self.key)

    def test_closed_request_has_no_tools_or_plaintext(self):
        from verification.evaluation import ROLES
        candidates = {r:{r+"-0":{"value":"synthetic", "transaction":"test"}} for r in ROLES}
        body = request_body(model="e2ee-example", prompt="Fixed public task", candidates=candidates,
                             verified_key=public_bytes(self.key))
        self.assertNotIn("tools", body)
        self.assertEqual(body["max_tokens"],512)
        self.assertNotIn("synthetic",json.dumps(body))
        self.assertEqual(decrypt_chunk(body["messages"][0]["content"],self.key), "Fixed public task")
        with self.assertRaises(Rejected):
            request_body(model="ordinary-model", prompt="Fixed task", candidates=candidates,
                          verified_key=public_bytes(self.key))


if __name__ == "__main__":
    unittest.main()
