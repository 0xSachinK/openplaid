import copy
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verification.common import Rejected
from verification.permits import issue, verify


class PermitTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.claims = {"audience":"openplaid-verification-v1", "attempt":"attempt-1", "ticket":"ticket-1",
                       "artifactDigest":"a"*64, "policyDigest":"b"*64, "enclaveKeyDigest":"c"*64,
                       "challenge":"d"*64, "expiresAt":int(time.time())+60, "maximumMicroUsd":50000}
        self.bindings = {"artifact_digest":"a"*64,"policy_digest":"b"*64,
                         "enclave_key_digest":"c"*64,"challenge":"d"*64}

    def test_signed_permit(self):
        self.assertEqual(verify(issue(self.claims,self.key),self.public,**self.bindings),self.claims)

    def test_other_enclave_and_tampered_budget_fail(self):
        permit=issue(self.claims,self.key)
        with self.assertRaisesRegex(Rejected,"permit_binding"):
            verify(permit,self.public,**{**self.bindings,"enclave_key_digest":"e"*64})
        permit["claims"]["maximumMicroUsd"]=1000
        with self.assertRaisesRegex(Rejected,"invalid_permit_signature"):
            verify(permit,self.public,**self.bindings)

    def test_expired_and_payment_audience_forbidden(self):
        for change in ({"expiresAt":0},{"audience":"payout"},{"maximumMicroUsd":50001}):
            with self.assertRaises(Rejected):
                issue({**self.claims,**change},self.key)


if __name__ == "__main__":
    unittest.main()
