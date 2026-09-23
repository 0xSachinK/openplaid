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
from verification.common import Rejected, b64, canonical, digest
from verification.control import Ledger
from verification.receipts import sign as sign_receipt, verify as verify_receipt
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

    def test_controller_permit_uses_verified_context_bound_quote(self):
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from verification.permits import verify as verify_permit
        ledger = Ledger(Path(self.directory.name) / "dispatch-ledger")
        try:
            release = {**self.release, "liveVerification": True}
            binding = {"revision": "a" * 64, "release": digest(release),
                       "policy": release["policyDigest"], "prompt": "c" * 64}
            ticket = ledger.create_ticket(award="synthetic-dispatch", contributor="tester",
                revision="a" * 64, capability="synthetic/bank", expires=int(time.time()) + 300)
            ledger.judge(ticket["id"], actor="operator", version=0, decision="admit", evidence_digest="d" * 64)
            attempt = ledger.reserve(ticket["id"], "request", binding, 1000)["id"]
            channel = SessionChannel()
            context = channel.challenge(attempt, digest(binding))
            doc = {**self.doc, "nonce": bytes.fromhex(digest(context)), "public_key": channel.public_key_der}
            signer = Ed25519PrivateKey.generate()
            permit = ledger.authorize_execution(attempt, context=context, attestation=self.encode(doc),
                public_key_der=channel.public_key_der, release=release, binding=binding, private_key=signer)
            claims = verify_permit(permit, signer.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                enclave_key_digest=hashlib.sha256(channel.public_key_der).hexdigest(),
                policy_digest=release["policyDigest"], artifact_digest="a" * 64, challenge=context["nonce"])
            self.assertEqual(claims["attempt"], attempt)
            with self.assertRaisesRegex(Rejected, "nonce_mismatch"):
                ledger.authorize_execution(attempt, context={**context, "nonce": "f" * 64},
                    attestation=self.encode(doc), public_key_der=channel.public_key_der,
                    release=release, binding=binding, private_key=signer)
        finally:
            ledger.db.close()

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

    def receipt_fixture(self):
        channel = SessionChannel()
        release = {**self.release, "liveVerification": True}
        document = self.encode({**self.doc, "public_key": channel.public_key_der})
        args = dict(attestation=document, nonce=b"n" * 32,
                    public_key_der=channel.public_key_der, release=release)
        binding = {"revision": "a" * 64, "release": digest(release),
                   "policy": release["policyDigest"], "prompt": "c" * 64}
        ledger = Ledger(Path(self.directory.name) / "receipts.sqlite3")
        self.addCleanup(ledger.db.close)
        ticket = ledger.create_ticket(award="test-award", contributor="test", revision="a" * 64,
                                     capability="synthetic-sent", expires=int(time.time())+600)
        ledger.judge(ticket["id"], actor="operator", version=0, decision="admit", evidence_digest="d"*64)
        attempt = ledger.reserve(ticket["id"], "request", binding, 50000)
        claims = {"audience": "openplaid-contribution-verification-v1", "attempt": attempt["id"],
                  "ticket": ticket["id"], "bindingDigest": digest(binding), "capability": "synthetic-sent",
                  "result": "verified", "issuedAt": int(time.time()), "expiresAt": int(time.time())+120}
        return channel, ledger, claims, binding, args

    def test_attested_receipt_records_success_once_without_acceptance_or_payment(self):
        channel, ledger, claims, binding, args = self.receipt_fixture()
        receipt = sign_receipt(claims, channel.key)
        ledger.finish_receipt(receipt, binding=binding, **args)
        version = ledger.ticket(claims["ticket"])["version"]
        ledger.finish_receipt(receipt, binding=binding, **args)
        ticket = ledger.ticket(claims["ticket"])
        self.assertEqual(ticket["version"], version)
        self.assertEqual(ticket["state"], "verified")
        self.assertEqual(ledger.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        conflicting = sign_receipt({**claims, "issuedAt": claims["issuedAt"]-1}, channel.key)
        with self.assertRaisesRegex(Rejected, "receipt_conflict"):
            ledger.finish_receipt(conflicting, binding=binding, **args)
        self.assertFalse(ledger.status()["payoutEnabled"])
        ledger.judge(claims["ticket"], actor="operator", version=version, decision="revoke",
                     evidence_digest="e"*64)
        with self.assertRaisesRegex(Rejected, "ticket_not_admitted"):
            ledger.finish_receipt(receipt, binding=binding, **args)

    def test_receipt_rejects_cross_contribution_and_release_rebinding(self):
        channel, ledger, claims, binding, args = self.receipt_fixture()
        for field, value in (("ticket", "other"), ("capability", "other"), ("bindingDigest", "f"*64)):
            receipt = sign_receipt({**claims, field:value}, channel.key)
            with self.subTest(field=field), self.assertRaisesRegex(Rejected, "receipt_binding"):
                ledger.finish_receipt(receipt, binding=binding, **args)
        receipt = sign_receipt(claims, channel.key)
        with self.assertRaisesRegex(Rejected, "receipt_binding"):
            ledger.finish_receipt(receipt, binding={**binding,"release":"f"*64}, **args)
        ledger.pause()
        with self.assertRaisesRegex(Rejected, "service_paused"):
            ledger.finish_receipt(receipt, binding=binding, **args)
        self.assertEqual(ledger.ticket(claims["ticket"])["state"], "admitted")

    def test_receipt_cannot_add_data_change_audience_or_forge_signature(self):
        channel, ledger, claims, binding, args = self.receipt_fixture()
        receipt = sign_receipt(claims, channel.key)
        cases = [{**receipt, "signature":b64(b"x"*384)},
                 {**receipt, "claims":{**claims, "audience":"payout"}},
                 {**receipt, "claims":{**claims, "bankAccount":"sensitive"}},
                 {**receipt, "claims":{**claims, "expiresAt":0}}]
        for modified in cases:
            with self.assertRaises(Rejected):
                verify_receipt(modified, **args)
        with self.assertRaises(Rejected):
            verify_receipt(receipt, **{**args, "nonce":b"x"*32})
        with self.assertRaises(Rejected):
            verify_receipt(receipt, **{**args, "release":self.release})


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
