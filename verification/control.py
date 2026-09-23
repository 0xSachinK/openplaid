"""Transactional operator-side admission and judgment. Never stores bank evidence.

SQLite is for one durable controller, not a database copied across replicas.
BEGIN IMMEDIATE serializes limits across processes. Paid dispatch is intentionally absent.
"""
import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager

from .common import canonical, digest, fields, hex_digest, identifier, require, strict_json
from .attestation import verify_document
from .admission import issue as issue_admission, validate as validate_admission
from .permits import issue as issue_permit, validate as validate_permit
from .receipts import verify as verify_receipt

MICRO_USD = 1_000_000


class Ledger:
    def __init__(self, path, task_cap=50 * MICRO_USD, inference_cap=5 * MICRO_USD):
        require(type(task_cap) is int and 0 < task_cap <= 50 * MICRO_USD, "invalid_budget")
        require(type(inference_cap) is int and 0 < inference_cap <= task_cap, "invalid_budget")
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
          PRAGMA journal_mode=WAL;
          PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS budget (
            id INTEGER PRIMARY KEY CHECK(id=1), task_cap INTEGER NOT NULL,
            inference_cap INTEGER NOT NULL, committed INTEGER NOT NULL DEFAULT 0,
            external_committed INTEGER NOT NULL DEFAULT 0, paused INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS tickets (
            id TEXT PRIMARY KEY, award TEXT UNIQUE NOT NULL, contributor TEXT NOT NULL,
            revision TEXT NOT NULL, capability TEXT NOT NULL, state TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
            committed INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS attempts (
            id TEXT PRIMARY KEY, ticket TEXT NOT NULL REFERENCES tickets(id),
            request_key TEXT NOT NULL, binding TEXT NOT NULL, reserved INTEGER NOT NULL,
            state TEXT NOT NULL, result TEXT, created INTEGER NOT NULL,
            UNIQUE(ticket, request_key));
          CREATE TABLE IF NOT EXISTS receipts (
            attempt TEXT PRIMARY KEY REFERENCES attempts(id), claims TEXT NOT NULL,
            signing_key_digest TEXT NOT NULL, release_digest TEXT NOT NULL,
            attestation_digest TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS execution_permits (
            attempt TEXT PRIMARY KEY REFERENCES attempts(id), context_digest TEXT NOT NULL,
            enclave_key_digest TEXT NOT NULL, challenge TEXT NOT NULL, permit TEXT NOT NULL,
            UNIQUE(enclave_key_digest, challenge));
          CREATE TABLE IF NOT EXISTS challenge_grants (
            attempt TEXT PRIMARY KEY REFERENCES attempts(id),
            enclave_key_digest TEXT NOT NULL, grant_json TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS judgments (
            id TEXT PRIMARY KEY, ticket TEXT NOT NULL, version INTEGER NOT NULL,
            actor TEXT NOT NULL, decision TEXT NOT NULL, evidence_digest TEXT NOT NULL,
            created INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, ref TEXT NOT NULL,
            payload TEXT NOT NULL, created INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS expenses (
            ref TEXT PRIMARY KEY, amount INTEGER NOT NULL, created INTEGER NOT NULL);
        """)
        self.db.execute("INSERT OR IGNORE INTO budget(id,task_cap,inference_cap) VALUES(1,?,?)",
                        (task_cap, inference_cap))
        row = self.db.execute("SELECT * FROM budget WHERE id=1").fetchone()
        require(row["task_cap"] == task_cap and row["inference_cap"] == inference_cap,
                "budget_configuration_mismatch")

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def event(self, kind, ref, payload):
        self.db.execute("INSERT INTO events(kind,ref,payload,created) VALUES(?,?,?,?)",
                        (kind, ref, canonical(payload).decode(), int(time.time())))

    def create_ticket(self, *, award, contributor, revision, capability, expires):
        for value in (award, contributor, capability):
            identifier(value)
        hex_digest(revision)
        require(type(expires) is int and int(time.time()) < expires <= int(time.time()) + 86400 * 14,
                "invalid_expiry")
        ticket = secrets.token_hex(16)
        with self.transaction():
            self.db.execute("INSERT INTO tickets(id,award,contributor,revision,capability,state,expires) "
                            "VALUES(?,?,?,?,?,'needs_review',?)",
                            (ticket, award, contributor, revision, capability, expires))
            self.event("ticket_created", ticket, {"award": award})
        return self.ticket(ticket)

    def ticket(self, ticket):
        row = self.db.execute("SELECT * FROM tickets WHERE id=?", (ticket,)).fetchone()
        require(row is not None, "unknown_ticket")
        return dict(row)

    def judge(self, ticket, *, actor, version, decision, evidence_digest):
        """Caller must be the authenticated operator. No contributor-facing auto-approval."""
        identifier(actor)
        hex_digest(evidence_digest)
        require(type(version) is int, "invalid_version")
        transitions = {"admit": ("needs_review", "admitted"),
                       "reject": ("needs_review", "rejected"),
                       "accept_contribution": ("verified", "accepted"),
                       "revoke": (None, "revoked")}
        require(decision in transitions, "invalid_decision")
        with self.transaction():
            row = self.ticket(ticket)
            origin, target = transitions[decision]
            require(row["version"] == version, "stale_judgment")
            require(row["expires"] > time.time(), "expired_ticket")
            require(origin is None or row["state"] == origin, "invalid_transition")
            require(row["state"] not in ("revoked", "rejected", "accepted"), "terminal_ticket")
            require(not self.db.execute("SELECT 1 FROM attempts WHERE ticket=? AND state='reserved'",
                                        (ticket,)).fetchone() or decision == "revoke", "active_attempt")
            self.db.execute("UPDATE tickets SET state=?,version=version+1 WHERE id=?", (target, ticket))
            self.db.execute("INSERT INTO judgments VALUES(?,?,?,?,?,?,?)",
                            (secrets.token_hex(16), ticket, version, actor, decision,
                             evidence_digest, int(time.time())))
            self.event("judgment", ticket, {"actor": actor, "decision": decision,
                                            "evidenceDigest": evidence_digest})
        return self.ticket(ticket)

    def reserve(self, ticket, request_key, binding, maximum_micro_usd):
        """Conservative: even failed/uncertain requests consume the full reservation.

        Retries return the same attempt. A new code revision does not create a fresh award.
        """
        identifier(request_key)
        fields(binding, ("revision", "release", "policy", "prompt"))
        for value in binding.values():
            hex_digest(value)
        require(type(maximum_micro_usd) is int and 0 < maximum_micro_usd <= 50_000,
                "attempt_budget")
        bound = digest(binding)
        with self.transaction():
            row = self.ticket(ticket)
            require(row["expires"] > time.time(), "expired_ticket")
            require(row["state"] == "admitted", "ticket_not_admitted")
            require(row["revision"] == binding["revision"], "revision_mismatch")
            existing = self.db.execute("SELECT * FROM attempts WHERE ticket=? AND request_key=?",
                                       (ticket, request_key)).fetchone()
            if existing:
                require(existing["binding"] == bound and existing["reserved"] == maximum_micro_usd,
                        "idempotency_conflict")
                return dict(existing)
            budget = self.db.execute("SELECT * FROM budget WHERE id=1").fetchone()
            require(not budget["paused"], "service_paused")
            require(row["attempts"] < 5 and row["committed"] + maximum_micro_usd <= 250_000,
                    "ticket_budget")
            require(budget["committed"] + maximum_micro_usd <= budget["inference_cap"] and
                    budget["committed"] + budget["external_committed"] + maximum_micro_usd <=
                    budget["task_cap"], "task_budget")
            require(not self.db.execute("SELECT 1 FROM attempts WHERE ticket=? AND state='reserved'",
                                        (ticket,)).fetchone(), "active_attempt")
            attempt = secrets.token_hex(16)
            self.db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,'reserved',NULL,?)",
                            (attempt, ticket, request_key, bound, maximum_micro_usd, int(time.time())))
            self.db.execute("UPDATE tickets SET attempts=attempts+1,committed=committed+? WHERE id=?",
                            (maximum_micro_usd, ticket))
            self.db.execute("UPDATE budget SET committed=committed+? WHERE id=1", (maximum_micro_usd,))
            self.event("reserved", attempt, {"maximumMicroUsd": maximum_micro_usd})
            return dict(self.db.execute("SELECT * FROM attempts WHERE id=?", (attempt,)).fetchone())

    def authorize_challenge(self, attempt, *, attestation, nonce, public_key_der,
                            release, binding, private_key):
        """Trusted controller: caller supplies its fresh random quote nonce and pinned release.

        Persist before returning; a restart or expired grant cannot move the same
        reservation to a new enclave. No owner secrets are needed for this step.
        """
        require(isinstance(nonce, bytes) and len(nonce) == 32, "nonce_size")
        fields(binding, ("revision", "release", "policy", "prompt"))
        for value in binding.values():
            hex_digest(value)
        require(release.get("liveVerification") is True and binding["release"] == digest(release) and
                binding["policy"] == release.get("policyDigest"), "permit_release")
        verify_document(attestation, nonce=nonce, public_key_der=public_key_der, release=release)
        key_digest = hashlib.sha256(public_key_der).hexdigest()
        with self.transaction():
            row = self.db.execute("SELECT * FROM attempts WHERE id=?", (attempt,)).fetchone()
            require(row is not None and row["state"] == "reserved", "attempt_not_reserved")
            ticket = self.ticket(row["ticket"])
            require(ticket["state"] == "admitted" and ticket["expires"] > time.time(),
                    "ticket_not_admitted")
            require(not self.db.execute("SELECT paused FROM budget WHERE id=1").fetchone()[0],
                    "service_paused")
            require(row["binding"] == digest(binding) and ticket["revision"] == binding["revision"],
                    "permit_binding")
            existing = self.db.execute("SELECT * FROM challenge_grants WHERE attempt=?", (attempt,)).fetchone()
            if existing:
                require(existing["enclave_key_digest"] == key_digest, "admission_already_issued")
                grant = strict_json(existing["grant_json"])
                validate_admission(grant["claims"])
            else:
                grant = issue_admission({"audience": "openplaid-challenge-v1", "attempt": attempt,
                    "bindingDigest": row["binding"], "policyDigest": binding["policy"],
                    "enclaveKeyDigest": key_digest,
                    "expiresAt": min(ticket["expires"], int(release["expiresAt"]), int(time.time()) + 120)},
                    private_key)
                self.db.execute("INSERT INTO challenge_grants VALUES(?,?,?)",
                                (attempt, key_digest, canonical(grant).decode()))
                self.event("challenge_authorized", attempt, {"grantDigest": digest(grant),
                                                            "enclaveKeyDigest": key_digest})
        return grant

    def authorize_execution(self, attempt, *, context, attestation, public_key_der,
                            release, binding, private_key):
        """Trusted controller only: persist one permit after verifying a fresh enclave quote.

        The attestation nonce is SHA256(canonical(context)), binding the exact challenge.
        Retries return the stored permit, never extend expiry or mint a replacement.
        The live enclave must still consume that challenge before any work or inference.
        """
        fields(context, ("protocol", "attempt", "bindingDigest", "nonce", "expiresAt"))
        require(context["protocol"] == "openplaid-session-v1" and context["attempt"] == attempt,
                "permit_context")
        hex_digest(context["nonce"])
        require(type(context["expiresAt"]) is int and
                time.time() < context["expiresAt"] <= time.time() + 120, "permit_expired")
        fields(binding, ("revision", "release", "policy", "prompt"))
        for value in binding.values():
            hex_digest(value)
        require(release.get("liveVerification") is True and binding["release"] == digest(release) and
                binding["policy"] == release.get("policyDigest"), "permit_release")
        context_digest = digest(context)
        verify_document(attestation, nonce=bytes.fromhex(context_digest),
                        public_key_der=public_key_der, release=release)
        key_digest = hashlib.sha256(public_key_der).hexdigest()
        with self.transaction():
            row = self.db.execute("SELECT * FROM attempts WHERE id=?", (attempt,)).fetchone()
            require(row is not None and row["state"] == "reserved", "attempt_not_reserved")
            ticket = self.ticket(row["ticket"])
            require(ticket["state"] == "admitted" and ticket["expires"] > time.time(),
                    "ticket_not_admitted")
            require(not self.db.execute("SELECT paused FROM budget WHERE id=1").fetchone()[0],
                    "service_paused")
            require(row["binding"] == context["bindingDigest"] == digest(binding) and
                    ticket["revision"] == binding["revision"], "permit_binding")
            existing = self.db.execute("SELECT * FROM execution_permits WHERE attempt=?", (attempt,)).fetchone()
            if existing:
                require(existing["context_digest"] == context_digest and
                        existing["enclave_key_digest"] == key_digest, "permit_already_issued")
                permit = strict_json(existing["permit"])
                validate_permit(permit["claims"])
            else:
                admission = self.db.execute("SELECT * FROM challenge_grants WHERE attempt=?", (attempt,)).fetchone()
                require(admission is not None, "admission_required")
                grant = strict_json(admission["grant_json"])
                validate_admission(grant["claims"])
                require(admission["enclave_key_digest"] == key_digest and
                        grant["claims"]["bindingDigest"] == context["bindingDigest"] and
                        context["expiresAt"] <= grant["claims"]["expiresAt"], "admission_binding")
                require(not self.db.execute(
                    "SELECT 1 FROM execution_permits WHERE enclave_key_digest=? AND challenge=?",
                    (key_digest, context["nonce"])).fetchone(), "permit_challenge_reused")
                claims = {"audience": "openplaid-verification-v1", "attempt": attempt,
                          "ticket": row["ticket"], "artifactDigest": ticket["revision"],
                          "policyDigest": binding["policy"], "enclaveKeyDigest": key_digest,
                          "challenge": context["nonce"],
                          "expiresAt": min(context["expiresAt"], ticket["expires"],
                                           int(release["expiresAt"]), int(time.time()) + 120),
                          "maximumMicroUsd": row["reserved"]}
                permit = issue_permit(claims, private_key)
                self.db.execute("INSERT INTO execution_permits VALUES(?,?,?,?,?)",
                                (attempt, context_digest, key_digest, context["nonce"], canonical(permit).decode()))
                self.event("execution_authorized", attempt, {"permitDigest": digest(permit),
                           "enclaveKeyDigest": key_digest, "contextDigest": context_digest})
        return permit

    def finish(self, attempt, result):
        """Operator failure reconciliation only. Success requires an attested receipt."""
        require(result in ("contradicted", "needs_review", "blocked"), "signed_receipt_required")
        with self.transaction():
            self._finish(attempt, result)

    def finish_receipt(self, receipt, *, attestation, nonce, public_key_der, release, binding):
        """Authenticate before recording success; never expose trust inputs to contributors."""
        claims = verify_receipt(receipt, attestation=attestation, nonce=nonce,
                                public_key_der=public_key_der, release=release)
        fields(binding, ("revision", "release", "policy", "prompt"))
        for value in binding.values():
            hex_digest(value)
        require(binding["release"] == digest(release) and
                binding["policy"] == release["policyDigest"], "receipt_binding")
        with self.transaction():
            row = self.db.execute("SELECT * FROM attempts WHERE id=?", (claims["attempt"],)).fetchone()
            require(row is not None, "unknown_attempt")
            ticket = self.ticket(row["ticket"])
            require(claims["ticket"] == row["ticket"] and claims["bindingDigest"] == row["binding"] ==
                    digest(binding) and binding["revision"] == ticket["revision"] and
                    claims["capability"] == ticket["capability"], "receipt_binding")
            require(claims["issuedAt"] >= row["created"] - 5, "receipt_predates_attempt")
            key_digest = hashlib.sha256(public_key_der).hexdigest()
            authorization = self.db.execute(
                "SELECT * FROM execution_permits WHERE attempt=?", (claims["attempt"],)).fetchone()
            require(authorization is not None, "receipt_execution_required")
            require(authorization["enclave_key_digest"] == key_digest,
                    "receipt_execution_key")
            # Reconciliation may happen after the permit expires, but execution
            # and signing must finish within its original, non-renewable window.
            permit_claims = strict_json(authorization["permit"])["claims"]
            require(claims["issuedAt"] < permit_claims["expiresAt"], "receipt_execution_expired")
            previous = self.db.execute("SELECT * FROM receipts WHERE attempt=?", (claims["attempt"],)).fetchone()
            encoded = canonical(claims).decode()
            if previous:
                require(previous["claims"] == encoded and previous["signing_key_digest"] == key_digest,
                        "receipt_conflict")
            self._finish(claims["attempt"], claims["result"])
            if not previous:
                self.db.execute("INSERT INTO receipts VALUES(?,?,?,?,?)",
                                (claims["attempt"], encoded, key_digest, digest(release),
                                 hashlib.sha256(attestation).hexdigest()))
                self.event("receipt_verified", claims["attempt"], {"claimsDigest": digest(claims),
                           "signingKeyDigest": key_digest, "releaseDigest": digest(release)})

    def _finish(self, attempt, result):
        # Only invoked inside a transaction by authenticated receipt/failure paths.
        row = self.db.execute("SELECT * FROM attempts WHERE id=?", (attempt,)).fetchone()
        require(row is not None, "unknown_attempt")
        ticket = self.ticket(row["ticket"])
        require(ticket["state"] not in ("revoked", "rejected") and ticket["expires"] > time.time(),
                "ticket_not_admitted")
        require(not self.db.execute("SELECT paused FROM budget WHERE id=1").fetchone()[0],
                "service_paused")
        if row["state"] == "finished":
            require(row["result"] == result, "result_conflict")
            return
        require(ticket["state"] == "admitted", "ticket_not_admitted")
        self.db.execute("UPDATE attempts SET state='finished',result=? WHERE id=?", (result, attempt))
        state = "verified" if result == "verified" else "needs_review"
        self.db.execute("UPDATE tickets SET state=?,version=version+1 WHERE id=?", (state, row["ticket"]))
        self.event("finished", attempt, {"result": result})

    def reserve_external(self, ref, amount):
        """Reserve infrastructure/API purchase upper bounds BEFORE spending, no refunds on uncertainty."""
        identifier(ref)
        require(type(amount) is int and amount > 0, "invalid_budget")
        with self.transaction():
            previous = self.db.execute("SELECT amount FROM expenses WHERE ref=?", (ref,)).fetchone()
            if previous:
                require(previous["amount"] == amount, "idempotency_conflict")
                return
            row = self.db.execute("SELECT * FROM budget WHERE id=1").fetchone()
            require(row["committed"] + row["external_committed"] + amount <= row["task_cap"], "task_budget")
            self.db.execute("INSERT INTO expenses VALUES(?,?,?)", (ref, amount, int(time.time())))
            self.db.execute("UPDATE budget SET external_committed=external_committed+? WHERE id=1", (amount,))
            self.event("external_reserved", ref, {"maximumMicroUsd": amount})

    def pause(self):
        with self.transaction():
            self.db.execute("UPDATE budget SET paused=1 WHERE id=1")
            self.event("paused", "service", {})

    def status(self):
        budget = dict(self.db.execute("SELECT * FROM budget WHERE id=1").fetchone())
        return {"schemaVersion": "1", "budget": budget, "schedulerEnabled": False,
                "payoutEnabled": False,
                "queue": [dict(r) for r in self.db.execute(
                    "SELECT id,award,revision,capability,state,version,expires FROM tickets "
                    "WHERE state IN ('needs_review','verified') ORDER BY expires")]}
