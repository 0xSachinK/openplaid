"""Transactional operator-side admission and judgment. Never stores bank evidence.

SQLite is for one durable controller, not a database copied across replicas.
BEGIN IMMEDIATE serializes limits across processes. Paid dispatch is intentionally absent.
"""
import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager

from .common import canonical, digest, fields, hex_digest, identifier, require
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
            previous = self.db.execute("SELECT * FROM receipts WHERE attempt=?", (claims["attempt"],)).fetchone()
            encoded = canonical(claims).decode()
            key_digest = hashlib.sha256(public_key_der).hexdigest()
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
