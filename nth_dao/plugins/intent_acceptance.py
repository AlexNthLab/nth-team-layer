"""Bounded local acceptance journal, never an execution or permission grant.

SQLite is node-local coordination state, not a file to merge between peers.
The Host owns the directory, policy resolver and clock. This is not a sandbox
against another process with permission to replace the database or its parents.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time

from nth_dao.canonical_json import canonical_json
from nth_dao.util.path_security import path_is_linklike

from .intent_envelope import (
    INTENT_ENVELOPE_MAX_DOCUMENT_BYTES,
    IntentAcceptanceContext,
    IntentEnvelopeError,
    _verified_document,
    verify_intent_envelope,
)


_APPLICATION_ID = 0x4E544849
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_SAFE_INTEGER = 2**53 - 1
_MAX_CONTEXT_BYTES = 8192
_MAX_SNAPSHOT_ATTEMPTS = 4
_COLUMNS = (
    "sequence", "envelope_digest", "audience_did", "scope_id", "signer_did",
    "nonce", "revision", "envelope_json", "context_json", "accepted_at_ms",
    "previous_audit_digest", "audit_digest",
)
_TEXT_MAX_BYTES = (
    ("envelope_digest", 71), ("audience_did", 128), ("scope_id", 256),
    ("signer_did", 128), ("nonce", 32),
    ("envelope_json", INTENT_ENVELOPE_MAX_DOCUMENT_BYTES),
    ("context_json", _MAX_CONTEXT_BYTES),
    ("previous_audit_digest", 71), ("audit_digest", 71),
)
_INVALID_ROW_SQL = " OR ".join([
    *(f"typeof({field}) != 'text' OR LENGTH(CAST({field} AS BLOB)) > {maximum}"
      for field, maximum in _TEXT_MAX_BYTES),
    *(f"typeof({field}) != 'integer' OR {field} < {minimum} OR {field} > {_MAX_SAFE_INTEGER}"
      for field, minimum in (("sequence", 1), ("revision", 1), ("accepted_at_ms", 0))),
])
_TABLE_SQL = """
    CREATE TABLE acceptances (
        sequence INTEGER PRIMARY KEY,
        envelope_digest TEXT NOT NULL UNIQUE,
        audience_did TEXT NOT NULL, scope_id TEXT NOT NULL,
        signer_did TEXT NOT NULL, nonce TEXT NOT NULL, revision INTEGER NOT NULL,
        envelope_json TEXT NOT NULL, context_json TEXT NOT NULL,
        accepted_at_ms INTEGER NOT NULL,
        previous_audit_digest TEXT NOT NULL, audit_digest TEXT NOT NULL,
        UNIQUE (audience_did, scope_id, revision),
        UNIQUE (audience_did, scope_id, signer_did, nonce)
    )
"""
_TRIGGER_SQL = {
    f"no_{operation.lower()}": f"""
        CREATE TRIGGER no_{operation.lower()} BEFORE {operation} ON acceptances
        BEGIN SELECT RAISE(ABORT, 'acceptance journal is append-only'); END
    """
    for operation in ("UPDATE", "DELETE")
}
_UNIQUE_COLUMNS = (
    ("envelope_digest",), ("audience_did", "scope_id", "revision"),
    ("audience_did", "scope_id", "signer_did", "nonce"),
)


class IntentAcceptanceStoreError(RuntimeError):
    """Storage is invalid or unavailable; no acceptance may be inferred."""


class IntentAcceptanceBusy(IntentAcceptanceStoreError):
    """A concurrent local writer holds the journal."""


class IntentAcceptanceConflict(IntentAcceptanceStoreError):
    """A revision, nonce, or clock would violate the journal history."""


class IntentAcceptanceCapacity(IntentAcceptanceStoreError):
    """The configured logical journal limit has been reached."""


class IntentAcceptancePolicyUnavailable(RuntimeError):
    """Host policy storage failed; this is not an acceptance journal failure."""


def _hash(document: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()


@dataclass(frozen=True)
class IntentAcceptanceHead:
    revision: int
    digest: str


@dataclass(frozen=True)
class IntentAcceptanceRecord:
    sequence: int
    envelope_digest: str
    envelope_json: str
    context_json: str
    accepted_at_ms: int
    previous_audit_digest: str
    audit_digest: str

    @property
    def envelope(self) -> dict:
        return json.loads(self.envelope_json)

    @property
    def audit(self) -> dict:
        return {
            "format": "org.nth-dao.intent-acceptance-observation.v1",
            "event_type": "intent.accepted",
            "sequence": self.sequence,
            "envelope_digest": self.envelope_digest,
            "context_digest": "sha256:" + hashlib.sha256(self.context_json.encode()).hexdigest(),
            "accepted_at_ms": self.accepted_at_ms,
            "previous_audit_digest": self.previous_audit_digest,
            "authority": "none", "commit_authority": False, "executable": False,
        }


@dataclass(frozen=True)
class IntentAcceptanceResult:
    record: IntentAcceptanceRecord
    created: bool


class IntentAcceptanceStore:
    """Append-only local observations with atomic revision/nonce uniqueness.

    A callback must read trusted, current Host policy and return the expectations
    for the explicitly reviewed operation. It receives only the persisted scope
    head, not the wire envelope. It must not do network I/O or reenter this store.
    Its external policy source must remain stable until this transaction commits;
    SQLite cannot lock a separate governance database or a membership file.
    """

    def __init__(
        self, workspace: Path, *, timeout: float = 5.0,
        max_records: int = 1024, max_bytes: int = 16 * 1024 * 1024,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 30
        ):
            raise ValueError("timeout must be finite and within (0, 30]")
        for name, value, maximum in (
            ("max_records", max_records, 4096), ("max_bytes", max_bytes, 64 * 1024 * 1024),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} is outside the supported range")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be a trusted callable")
        self.workspace = Path(workspace).absolute()
        self.path = self.workspace / ".nth" / "intent_acceptance_v1" / "acceptance.sqlite3"
        self.timeout, self.max_records, self.max_bytes = float(timeout), max_records, max_bytes
        self._clock = clock if clock is not None else lambda: time.time_ns() // 1_000_000
        try:
            self._assert_path()
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            raise IntentAcceptanceStoreError("acceptance storage is unavailable") from None
        with self._transaction(write=True, initialize=True) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                application = connection.execute("PRAGMA application_id").fetchone()[0]
                if application != 0 or connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                    raise IntentAcceptanceStoreError("unrecognized nonempty acceptance database")
                connection.execute(_TABLE_SQL)
                for statement in _TRIGGER_SQL.values():
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                connection.execute("PRAGMA user_version = 1")
            self._check_schema(connection)
        self._read_history()

    def _assert_path(self) -> None:
        for candidate in (*self.path.parents, self.path):
            if path_is_linklike(candidate):
                raise IntentAcceptanceStoreError("acceptance storage must not contain links")
        for suffix in ("-wal", "-shm", "-journal"):
            if path_is_linklike(Path(str(self.path) + suffix)):
                raise IntentAcceptanceStoreError("acceptance sidecars must not contain links")

    @staticmethod
    def _check_schema(connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        application = connection.execute("PRAGMA application_id").fetchone()[0]
        if version != 1 or application != _APPLICATION_ID:
            raise IntentAcceptanceStoreError("unsupported acceptance database format")
        # This private v1 database has a closed schema, including trigger bodies.
        # Whitespace-only DDL formatting from the original writer remains valid.
        expected = {("table", "acceptances", "acceptances"): " ".join(_TABLE_SQL.split())}
        expected.update({
            ("trigger", name, "acceptances"): " ".join(sql.split())
            for name, sql in _TRIGGER_SQL.items()
        })
        expected.update({
            ("index", f"sqlite_autoindex_acceptances_{i}", "acceptances"): None
            for i in range(1, 4)
        })
        rows = connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master LIMIT 7").fetchall()
        actual = {(r["type"], r["name"], r["tbl_name"]): " ".join(r["sql"].split()) if r["sql"] is not None else None for r in rows}
        if len(rows) != len(expected) or actual != expected:
            raise IntentAcceptanceStoreError("acceptance schema integrity check failed")
        for i, names in enumerate(_UNIQUE_COLUMNS, 1):
            columns = connection.execute(f"PRAGMA index_xinfo('sqlite_autoindex_acceptances_{i}')").fetchall()
            keys = [(r["name"], r["desc"], r["coll"]) for r in columns if r["key"]]
            if keys != [(name, 0, "BINARY") for name in names]:
                raise IntentAcceptanceStoreError("acceptance index schema integrity check failed")

    @contextmanager
    def _transaction(self, *, write: bool = False, initialize: bool = False) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            try:
                self._assert_path()
            except OSError:
                raise IntentAcceptanceStoreError("acceptance storage is unavailable") from None
            target = str(self.path) if initialize else self.path.as_uri() + "?mode=rw"
            connection = sqlite3.connect(target, uri=not initialize, timeout=self.timeout, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if not initialize:
                self._check_schema(connection)
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            code = getattr(exc, "sqlite_errorcode", 0)
            if code & 0xFF in {getattr(sqlite3, "SQLITE_BUSY", 5), getattr(sqlite3, "SQLITE_LOCKED", 6)} or str(exc).lower() in {
                "database is locked", "database table is locked",
            }:
                raise IntentAcceptanceBusy("acceptance journal is busy") from None
            raise IntentAcceptanceStoreError("acceptance database operation failed") from None
        finally:
            if connection is not None:
                # Closing rolls back any exception path, including Host policy failures.
                connection.close()

    def _read_rows(self, connection: sqlite3.Connection) -> tuple[sqlite3.Row, ...]:
        # Only scalar aggregates cross into Python until every field is bounded.
        # BLOB lengths count UTF-8 bytes, including data after embedded NULs.
        count, size, invalid = connection.execute(f"""
            SELECT COUNT(*), COALESCE(SUM(
                LENGTH(CAST(envelope_json AS BLOB)) + LENGTH(CAST(context_json AS BLOB))
            ), 0), COALESCE(MAX(CASE WHEN {_INVALID_ROW_SQL} THEN 1 ELSE 0 END), 0)
            FROM acceptances NOT INDEXED
        """).fetchone()
        if invalid:
            raise IntentAcceptanceStoreError("acceptance field type or byte-limit integrity check failed")
        if count > self.max_records or size > self.max_bytes:
            raise IntentAcceptanceCapacity("acceptance journal exceeds configured capacity")
        return tuple(connection.execute(f"SELECT {', '.join(_COLUMNS)} FROM acceptances ORDER BY sequence"))

    def _read_history(self) -> tuple[tuple[sqlite3.Row, ...], list[IntentAcceptanceRecord]]:
        with self._transaction() as connection:
            rows = self._read_rows(connection)
        # No SQLite read or writer lock is held during cryptographic verification.
        return rows, self._verify_rows(rows)

    @staticmethod
    def _verify_rows(rows: tuple[sqlite3.Row, ...]) -> list[IntentAcceptanceRecord]:
        records, heads, nonces = [], {}, set()
        previous, timestamp = "", 0
        for row in rows:
            try:
                if any(type(row[key]) is not str for key in (
                    "envelope_digest", "envelope_json", "context_json", "previous_audit_digest",
                    "audit_digest", "audience_did", "scope_id", "signer_did", "nonce",
                )) or any(type(row[key]) is not int for key in ("sequence", "accepted_at_ms", "revision")):
                    raise ValueError("invalid journal field type")
                record = IntentAcceptanceRecord(**{key: row[key] for key in (
                    "sequence", "envelope_digest", "envelope_json", "context_json",
                    "accepted_at_ms", "previous_audit_digest", "audit_digest",
                )})
                if len(record.envelope_json.encode()) > INTENT_ENVELOPE_MAX_DOCUMENT_BYTES or len(record.context_json.encode()) > _MAX_CONTEXT_BYTES:
                    raise ValueError("oversized journal row")
                envelope, context = record.envelope, json.loads(record.context_json)
                if type(context) is not dict or type(context.get("allowed_solver_classes")) is not list:
                    raise ValueError("invalid context")
                expected_fields = context | {
                    "allowed_solver_classes": tuple(context["allowed_solver_classes"]),
                }
                # Records written before the Host policy gate predate this
                # observation-only provenance field. Preserve their original
                # canonical bytes while treating them as explicitly unbound.
                expected_fields.setdefault("authorization_digest", "")
                expected = IntentAcceptanceContext(**expected_fields)
                verify_intent_envelope(envelope, expected=expected, now_ms=record.accepted_at_ms)
                if canonical_json(envelope).decode() != record.envelope_json or canonical_json(context).decode() != record.context_json:
                    raise ValueError("noncanonical row")
                if record.envelope_digest != _hash(envelope) or record.audit_digest != _hash(record.audit):
                    raise ValueError("row digest mismatch")
                if record.sequence != len(records) + 1 or record.previous_audit_digest != previous or record.accepted_at_ms < timestamp:
                    raise ValueError("audit chain mismatch")
                if any(row[key] != envelope[key] for key in ("audience_did", "scope_id", "signer_did", "nonce", "revision")):
                    raise ValueError("index binding mismatch")
                scope = (envelope["audience_did"], envelope["scope_id"])
                head = heads.get(scope, IntentAcceptanceHead(0, ""))
                if envelope["revision"] != head.revision + 1 or envelope["previous_digest"] != head.digest:
                    raise ValueError("revision chain mismatch")
                nonce = (*scope, envelope["signer_did"], envelope["nonce"])
                if nonce in nonces:
                    raise ValueError("duplicate nonce")
                nonces.add(nonce)
                heads[scope] = IntentAcceptanceHead(envelope["revision"], record.envelope_digest)
                previous, timestamp = record.audit_digest, record.accepted_at_ms
                records.append(record)
            except (IndexError, KeyError, TypeError, ValueError, RecursionError):
                raise IntentAcceptanceStoreError("acceptance journal integrity check failed") from None
        return records

    def accept(
        self, envelope: dict, *,
        resolve_context: Callable[[IntentAcceptanceHead], IntentAcceptanceContext],
    ) -> IntentAcceptanceResult:
        """Persist a live acceptance or return an exact existing artifact.

        The resolver runs under the writer lock on every call, including retry.
        Revoked or expired requests fail again. Use get() for historical recovery;
        reading a record never grants current authority or re-executes work.
        """
        if not callable(resolve_context):
            raise TypeError("a trusted Host context resolver is required")
        return self._accept(
            envelope,
            resolve_context=lambda head, _now: resolve_context(head),
            governed_policy=None,
        )

    def _accept_governed_snapshot(
        self,
        envelope: dict,
        *,
        policy: object,
        signer_did: str,
    ) -> IntentAcceptanceResult:
        """Accept under a store-selected policy snapshot and trusted clock.

        Callers must enter through ``accept_governed`` so current-head selection
        and this write share the policy store's cross-process lock.
        """

        from .intent_policy import IntentAcceptancePolicySnapshot

        if type(policy) is not IntentAcceptancePolicySnapshot:
            raise TypeError("policy must be an IntentAcceptancePolicySnapshot")
        if not isinstance(signer_did, str):
            raise TypeError("signer_did must be a string")
        return self._accept(
            envelope,
            resolve_context=lambda head, now: policy.resolve(
                signer_did=signer_did,
                head=head,
                now_ms=now,
            ),
            governed_policy=policy,
        )

    def accept_governed(
        self,
        envelope: dict,
        *,
        policy_store: object,
        signer_did: str,
        expected_policy_tail_digest: str,
    ) -> IntentAcceptanceResult:
        """Accept only under the persisted current policy for this wire scope."""

        policy_store = self._require_local_policy_store(policy_store)
        snapshot = _verified_document(envelope)
        with policy_store.coordination_lock():
            try:
                policy_store._require_tail_unlocked(expected_policy_tail_digest)
            except ValueError:
                raise
            except RuntimeError:
                raise IntentAcceptancePolicyUnavailable(
                    "policy history does not match the retained tail"
                ) from None
            policy = policy_store._current_unlocked(
                snapshot["audience_did"],
                snapshot["scope_id"],
            )
            if policy is None:
                raise IntentAcceptancePolicyUnavailable(
                    "no current policy exists for the envelope audience and scope"
                )
            return self._accept_governed_snapshot(
                snapshot,
                policy=policy,
                signer_did=signer_did,
            )

    def verify_governed_history(
        self,
        *,
        policy_store: object,
        expected_policy_tail_digest: str | None = None,
    ) -> tuple[int, str, int, str]:
        """Verify journal integrity and every retained governance observation.

        The returned tuple is ``(acceptance_count, acceptance_tail,
        policy_count, policy_tail)``. Legacy records with an empty
        ``authorization_digest`` remain explicitly unbound and are not promoted
        to governed records by this audit.
        """

        policy_store = self._require_local_policy_store(policy_store)
        with policy_store.coordination_lock():
            policies = policy_store.history()
            policy_tail = policies[-1].audit_digest if policies else ""
            if expected_policy_tail_digest is not None:
                if (
                    type(expected_policy_tail_digest) is not str
                    or (
                        expected_policy_tail_digest != ""
                        and _HASH.fullmatch(expected_policy_tail_digest) is None
                    )
                ):
                    raise ValueError(
                        "expected_policy_tail_digest must be a content hash or empty genesis marker"
                    )
                if policy_tail != expected_policy_tail_digest:
                    raise IntentAcceptancePolicyUnavailable(
                        "policy history does not match the retained tail"
                    )
            _rows, acceptances = self._read_history()
            policy_by_digest = {record.digest: record for record in policies}
            scope_heads: dict[tuple[str, str], IntentAcceptanceHead] = {}
            for acceptance in acceptances:
                envelope = acceptance.envelope
                context_document = json.loads(acceptance.context_json)
                authorization_digest = context_document.get("authorization_digest", "")
                scope = (envelope["audience_did"], envelope["scope_id"])
                prior_head = scope_heads.get(scope, IntentAcceptanceHead(0, ""))
                if authorization_digest:
                    policy_record = policy_by_digest.get(authorization_digest)
                    if policy_record is None:
                        raise IntentAcceptancePolicyUnavailable(
                            "governed acceptance references a missing policy"
                        )
                    if policy_record.stored_at_ms > acceptance.accepted_at_ms:
                        raise IntentAcceptancePolicyUnavailable(
                            "governed acceptance predates its policy publication"
                        )
                    expected = policy_record.policy.resolve(
                        signer_did=envelope["signer_did"],
                        head=prior_head,
                        now_ms=acceptance.accepted_at_ms,
                    )
                    expected_document = asdict(expected)
                    expected_document["allowed_solver_classes"] = list(
                        expected.allowed_solver_classes
                    )
                    if context_document != expected_document:
                        raise IntentAcceptancePolicyUnavailable(
                            "governed acceptance context does not match its retained policy"
                        )
                scope_heads[scope] = IntentAcceptanceHead(
                    envelope["revision"], acceptance.envelope_digest
                )
        acceptance_tail = acceptances[-1].audit_digest if acceptances else ""
        return len(acceptances), acceptance_tail, len(policies), policy_tail

    def _require_local_policy_store(self, policy_store: object):
        from .intent_policy_store import IntentPolicyStore

        if type(policy_store) is not IntentPolicyStore:
            raise TypeError("policy_store must be an IntentPolicyStore")
        acceptance_workspace = os.path.normcase(str(self.workspace.resolve()))
        policy_workspace = os.path.normcase(str(policy_store.workspace.resolve()))
        if policy_workspace != acceptance_workspace:
            raise IntentAcceptancePolicyUnavailable(
                "policy store belongs to a different workspace"
            )
        return policy_store

    def _accept(
        self,
        envelope: dict,
        *,
        resolve_context: Callable[[IntentAcceptanceHead, int], IntentAcceptanceContext],
        governed_policy: object | None,
    ) -> IntentAcceptanceResult:
        snapshot = _verified_document(envelope)
        for _attempt in range(_MAX_SNAPSHOT_ATTEMPTS):
            rows, records = self._read_history()
            head = IntentAcceptanceHead(0, "")
            for record in records:
                prior = record.envelope
                if (prior["audience_did"], prior["scope_id"]) == (snapshot["audience_did"], snapshot["scope_id"]):
                    head = IntentAcceptanceHead(prior["revision"], record.envelope_digest)
            usage = sum(len(r.envelope_json.encode()) + len(r.context_json.encode()) for r in records)
            with self._transaction(write=True) as connection:
                # Compare all persisted fields, not only the tail or a row count.
                if self._read_rows(connection) != rows:
                    continue
                result = self._accept_current(
                    connection,
                    snapshot,
                    records,
                    head,
                    usage,
                    resolve_context,
                    governed_policy,
                )
            return result
        raise IntentAcceptanceBusy("acceptance journal kept changing; retry with a fresh snapshot")

    def _accept_current(
        self, connection: sqlite3.Connection, snapshot: dict,
        records: list[IntentAcceptanceRecord], head: IntentAcceptanceHead, usage: int,
        resolve_context: Callable[[IntentAcceptanceHead, int], IntentAcceptanceContext],
        governed_policy: object | None,
    ) -> IntentAcceptanceResult:
        now = self._read_clock()
        try:
            expected = resolve_context(head, now)
        except sqlite3.Error:
            # Do not let the outer journal transaction misclassify a policy DB.
            raise IntentAcceptancePolicyUnavailable("Host policy storage is unavailable") from None
        if type(expected) is not IntentAcceptanceContext:
            raise IntentEnvelopeError("Host resolver must return an IntentAcceptanceContext")
        if governed_policy is None:
            if expected.authorization_digest != "":
                raise IntentEnvelopeError(
                    "governed authorization requires accept_governed()"
                )
        else:
            from .intent_policy import IntentAcceptancePolicySnapshot

            if type(governed_policy) is not IntentAcceptancePolicySnapshot:
                raise IntentEnvelopeError("governed policy type changed during acceptance")
            if expected.authorization_digest != governed_policy.digest:
                raise IntentEnvelopeError("authorization digest does not match the policy snapshot")
        document = verify_intent_envelope(snapshot, expected=expected, now_ms=now)
        digest = _hash(document)
        existing = next((r for r in records if r.envelope_digest == digest), None)
        if existing is not None:
            return IntentAcceptanceResult(existing, created=False)
        if document["revision"] != head.revision + 1 or document["previous_digest"] != head.digest:
            raise IntentAcceptanceConflict("accepted revision head has changed")
        if connection.execute("""
            SELECT 1 FROM acceptances WHERE audience_did=? AND scope_id=? AND signer_did=? AND nonce=?
        """, tuple(document[key] for key in ("audience_did", "scope_id", "signer_did", "nonce"))).fetchone():
            raise IntentAcceptanceConflict("nonce has already been consumed in this scope")
        if records and now < records[-1].accepted_at_ms:
            raise IntentAcceptanceConflict("Host clock moved backwards")
        context = asdict(expected)
        context["allowed_solver_classes"] = list(expected.allowed_solver_classes)
        envelope_json, context_json = canonical_json(document).decode(), canonical_json(context).decode()
        if len(context_json.encode()) > _MAX_CONTEXT_BYTES:
            raise IntentEnvelopeError("Host context exceeds the journal byte limit")
        if len(records) >= self.max_records or usage + len(envelope_json.encode()) + len(context_json.encode()) > self.max_bytes:
            raise IntentAcceptanceCapacity("acceptance journal capacity reached")
        commit_time = self._read_clock()
        if not document["issued_at_ms"] <= commit_time < document["expires_at_ms"]:
            raise IntentEnvelopeError("envelope expired before the insert boundary")
        if governed_policy is not None and not governed_policy.is_valid_at(commit_time):
            raise IntentEnvelopeError("authorization policy expired before the insert boundary")
        if commit_time < now:
            raise IntentAcceptanceConflict("Host clock moved backwards before insertion")
        record = IntentAcceptanceRecord(
            len(records) + 1, digest, envelope_json, context_json, commit_time,
            records[-1].audit_digest if records else "", "",
        )
        record = IntentAcceptanceRecord(**(asdict(record) | {"audit_digest": _hash(record.audit)}))
        self._insert(connection, record)
        return IntentAcceptanceResult(record, created=True)

    def _read_clock(self) -> int:
        now = self._clock()
        if type(now) is not int or not 0 <= now <= _MAX_SAFE_INTEGER:
            raise IntentEnvelopeError("Host clock must return a nonnegative safe integer")
        return now

    @staticmethod
    def _insert(connection: sqlite3.Connection, record: IntentAcceptanceRecord) -> None:
        envelope = record.envelope
        values = asdict(record) | {key: envelope[key] for key in (
            "audience_did", "scope_id", "signer_did", "nonce", "revision",
        )}
        cursor = connection.execute(f"""
            INSERT INTO acceptances ({', '.join(_COLUMNS)}) VALUES (
                :sequence, :envelope_digest, :audience_did, :scope_id, :signer_did,
                :nonce, :revision, :envelope_json, :context_json, :accepted_at_ms,
                :previous_audit_digest, :audit_digest
            )
        """, values)
        if cursor.rowcount != 1:
            raise IntentAcceptanceStoreError("acceptance insert did not write exactly one record")
        persisted = connection.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM acceptances WHERE sequence=?", (record.sequence,),
        ).fetchone()
        if persisted is None or any(
            type(persisted[i]) is not type(values[key]) or persisted[i] != values[key]
            for i, key in enumerate(_COLUMNS)
        ):
            raise IntentAcceptanceStoreError("acceptance insert readback mismatch")

    def get(self, envelope_digest: str) -> IntentAcceptanceRecord | None:
        if type(envelope_digest) is not str or _HASH.fullmatch(envelope_digest) is None:
            raise ValueError("envelope_digest must be a content hash")
        _rows, records = self._read_history()
        return next((r for r in records if r.envelope_digest == envelope_digest), None)

    def _lookup_with_scope_head(
        self,
        envelope_digest: str,
    ) -> tuple[IntentAcceptanceRecord | None, IntentAcceptanceRecord | None]:
        """Return one verified record and its verified scope head in one snapshot."""

        if type(envelope_digest) is not str or _HASH.fullmatch(envelope_digest) is None:
            raise ValueError("envelope_digest must be a content hash")
        _rows, records = self._read_history()
        record = next(
            (item for item in records if item.envelope_digest == envelope_digest),
            None,
        )
        if record is None:
            return None, None
        envelope = record.envelope
        head = next(
            (
                item
                for item in reversed(records)
                if item.envelope["audience_did"] == envelope["audience_did"]
                and item.envelope["scope_id"] == envelope["scope_id"]
            ),
            None,
        )
        return record, head

    def history(self, *, after_sequence: int = 0, limit: int = 100) -> tuple[IntentAcceptanceRecord, ...]:
        if type(after_sequence) is not int or not 0 <= after_sequence <= _MAX_SAFE_INTEGER:
            raise ValueError("after_sequence must be a nonnegative safe integer")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be within 1..1000")
        _rows, records = self._read_history()
        return tuple(r for r in records if r.sequence > after_sequence)[:limit]

    def verify_history(self, *, expected_tail_digest: str | None = None) -> tuple[int, str]:
        """Check a captured history; an empty expected tail pins empty genesis."""
        if expected_tail_digest is not None and (
            type(expected_tail_digest) is not str
            or (expected_tail_digest != "" and _HASH.fullmatch(expected_tail_digest) is None)
        ):
            raise ValueError("expected_tail_digest must be a content hash or empty genesis marker")
        _rows, records = self._read_history()
        tail = records[-1].audit_digest if records else ""
        if expected_tail_digest is not None and tail != expected_tail_digest:
            raise IntentAcceptanceStoreError("acceptance journal does not match the retained tail")
        return len(records), tail
