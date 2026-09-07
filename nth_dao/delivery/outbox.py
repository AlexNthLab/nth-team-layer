"""Durable outbox for signed transport envelopes (delivery layer v1).

Extracted as the generic delivery core from the patterns proven by
``nth_dao.commerce.outbox`` and ``nth_dao.trade_rules.execution_dispatch``,
per the integration design doc §9: commerce replication becomes one USER of
this core instead of every subsystem carrying its own outbox copy.

Guarantees:

* **Crash-safe** — every state change is one appended JSONL line, flushed
  and fsynced before the call returns. A process crash between "write" and
  "acknowledge" replays from the journal on the next load. A torn final
  line (crash mid-append) is ignored on recovery; corruption anywhere else
  fails closed.
* **Idempotent** — enqueueing the same ``message_id`` twice never creates a
  second record.
* **ACK-terminal** — one authorized signed ACK for the exact queued envelope
  marks it delivered and cancels every other in-flight copy.
* **Cross-process safe** — journal mutation happens under an
  ``InterProcessLock`` on the journal file.
* **Bounded** — non-terminal record count is capped; enqueue fails closed
  with :class:`DeliveryOutboxFull` instead of silently growing.

The outbox never interprets payloads. It stores canonical envelope bytes
and moves records between states; business semantics stay in the domain
layer exactly as the design doc §5.1 requires.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import (
    DeliveryAck,
    validate_ack,
)
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
    TransportEnvelopeRejected,
    envelope_digest,
    validate_envelope,
)
from nth_dao.util.io import InterProcessLock

logger = logging.getLogger("nth_dao.delivery")

PathLike = Union[str, Path]
AckAuthorizer = Callable[[DeliveryAck, TransportEnvelope], Tuple[bool, str]]

OUTBOX_STATE_QUEUED = "queued"
OUTBOX_STATE_DELIVERED = "delivered"
OUTBOX_STATE_REJECTED = "rejected"
OUTBOX_STATE_EXPIRED = "expired"
OUTBOX_TERMINAL_STATES = (OUTBOX_STATE_DELIVERED, OUTBOX_STATE_REJECTED, OUTBOX_STATE_EXPIRED)

OUTBOX_ATTEMPT_SENT = "sent"
OUTBOX_ATTEMPT_ERROR = "error"
OUTBOX_ATTEMPT_REJECTED = "rejected"
OUTBOX_ATTEMPT_OUTCOMES = (OUTBOX_ATTEMPT_SENT, OUTBOX_ATTEMPT_ERROR, OUTBOX_ATTEMPT_REJECTED)

DEFAULT_MAX_PENDING_RECORDS = 4_096
MAX_ATTEMPTS_PER_RECORD = 256
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
_JOURNAL_EVENTS = ("enqueued", "attempt", "delivered", "rejected", "expired")
_MESSAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRANSPORT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_EVENT_FIELDS = {
    "enqueued": frozenset(
        {
            "event",
            "message_id",
            "envelope_json",
            "envelope_sha256",
            "created_at_ms",
            "expires_at_ms",
            "at_ms",
        }
    ),
    "attempt": frozenset({"event", "message_id", "transport", "at_ms", "outcome"}),
    "delivered": frozenset({"event", "message_id", "at_ms", "ack_json"}),
    "rejected": frozenset(
        {"event", "message_id", "transport", "at_ms", "error_code"}
    ),
    "expired": frozenset({"event", "message_id", "at_ms"}),
}
MAX_ERROR_CODE_LENGTH = 256


class DeliveryOutboxError(RuntimeError):
    """Base error for outbox operation failures."""


class DeliveryOutboxFull(DeliveryOutboxError):
    """Raised when the pending-record cap is reached (fail closed)."""


class DeliveryOutboxCorrupt(DeliveryOutboxError):
    """Raised when the journal is damaged beyond a torn final line."""


@dataclass
class OutboxAttempt:
    transport: str
    at_ms: int
    outcome: str
    error_code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "transport": self.transport,
            "at_ms": self.at_ms,
            "outcome": self.outcome,
        }
        if self.error_code:
            data["error_code"] = self.error_code
        return data


@dataclass
class OutboxRecord:
    message_id: str
    envelope_json: str
    envelope_sha256: str
    created_at_ms: int
    expires_at_ms: int
    state: str = OUTBOX_STATE_QUEUED
    attempts: List[OutboxAttempt] = field(default_factory=list)
    delivered_by: str = ""
    delivered_at_ms: int = 0
    last_error_code: str = ""

    @property
    def is_terminal(self) -> bool:
        return self.state in OUTBOX_TERMINAL_STATES


def _validate_transport_name(value: Any) -> str:
    if not isinstance(value, str) or _TRANSPORT_NAME_RE.fullmatch(value) is None:
        raise DeliveryOutboxError("transport name must be a bounded identifier")
    return value


def _validate_error_code(value: Any) -> str:
    if not isinstance(value, str) or len(value) > MAX_ERROR_CODE_LENGTH:
        raise DeliveryOutboxError(
            f"error_code must be a string no longer than {MAX_ERROR_CODE_LENGTH} chars"
        )
    return value


def _validate_operation_time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DeliveryOutboxError(f"{name} must be a positive integer")
    return value


class DurableOutbox:
    """Append-only journal backed outbox for one workspace delivery dir."""

    def __init__(
        self,
        directory: PathLike,
        *,
        max_pending_records: int = DEFAULT_MAX_PENDING_RECORDS,
        clock: Optional[Callable[[], int]] = None,
        authorize_ack: Optional[AckAuthorizer] = None,
    ) -> None:
        self._dir = Path(directory)
        self._journal_path = self._dir / "outbox.journal.jsonl"
        self._lock_path = self._dir / "outbox.lock"
        self._max_pending = max_pending_records
        if (
            isinstance(max_pending_records, bool)
            or not isinstance(max_pending_records, int)
            or max_pending_records < 1
        ):
            raise ValueError("max_pending_records must be a positive integer")
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._authorize_ack = authorize_ack
        self._records: Dict[str, OutboxRecord] = {}
        self._thread_lock = threading.RLock()
        self._journal_stat: Optional[tuple] = None
        self._dir.mkdir(parents=True, exist_ok=True)
        with InterProcessLock(self._lock_path):
            self._load()

    # ─────────────────────── persistence ───────────────────────

    def _load(self) -> None:
        """Fold the journal. Tolerates a torn final line; corrupts loudly."""

        records: Dict[str, OutboxRecord] = {}
        if not self._journal_path.exists():
            self._records = records
            self._journal_stat = None
            return
        if self._journal_path.stat().st_size > MAX_JOURNAL_BYTES:
            raise DeliveryOutboxCorrupt(
                f"outbox journal exceeds {MAX_JOURNAL_BYTES} bytes; run compact() "
                "before loading (fail closed against disk-exhaustion floods)"
            )
        stat = self._journal_path.stat()
        self._journal_stat = (stat.st_mtime_ns, stat.st_size)
        raw = self._journal_path.read_bytes()
        lines = raw.split(b"\n")
        torn_tail = bool(raw) and not raw.endswith(b"\n")
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            is_last = index == len(lines) - 1
            if is_last and torn_tail:
                logger.warning(
                    "delivery outbox journal has a torn final line; ignoring it "
                    "(crash during append) — %s", self._journal_path,
                )
                break
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise DeliveryOutboxCorrupt(
                    f"corrupt journal line {index + 1} in {self._journal_path}: {exc}"
                ) from exc
            if not isinstance(event, dict):
                raise DeliveryOutboxCorrupt(f"journal line {index + 1} is not an object")
            _fold_event(records, event)
        self._records = records

    def _refold_if_changed(self) -> None:
        """Re-fold the journal when another process mutated it on disk.

        Every mutation is journaled before it is applied in memory, so a
        re-fold is always safe and keeps enqueue idempotency, expiry, and
        compaction correct across processes.
        """

        try:
            if not self._journal_path.exists():
                return
            stat = self._journal_path.stat()
        except OSError:
            return
        current = (stat.st_mtime_ns, stat.st_size)
        if current != self._journal_stat:
            logger.debug("delivery outbox journal changed on disk; re-folding")
            self._records = {}
            self._load()

    def _append_locked(self, event: Dict[str, Any]) -> None:
        """Append while the caller holds ``self._lock_path``.

        State-changing operations deliberately hold one process lock across
        refold, validation, append, and the in-memory update. Locking only
        this write would leave a check-then-append race between processes.
        """

        line = canonical_json(event) + b"\n"
        with open(self._journal_path, "ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
            # capture our fingerprint while STILL holding the lock: a stat
            # taken after release could absorb another process's append and
            # permanently hide it from the re-fold check (round-4 bug Q)
            try:
                stat = os.fstat(handle.fileno())
                self._journal_stat = (stat.st_mtime_ns, stat.st_size)
            except OSError:  # pragma: no cover - fstat on our own fd
                pass

    # ─────────────────────── queries ───────────────────────

    def get(self, message_id: str) -> Optional[OutboxRecord]:
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                record = self._records.get(message_id)
                return _copy_record(record) if record else None

    def pending(self, now_ms: Optional[int] = None) -> List[OutboxRecord]:
        """Non-terminal records; expired ones are folded to expired first."""

        now = _validate_operation_time(
            self._clock() if now_ms is None else now_ms, "now_ms"
        )
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                expired = [
                    record
                    for record in self._records.values()
                    if record.state == OUTBOX_STATE_QUEUED
                    and record.expires_at_ms <= now
                ]
                for record in expired:
                    self._transition_expired(record, now)
                return [
                    _copy_record(record)
                    for record in self._records.values()
                    if record.state == OUTBOX_STATE_QUEUED
                ]

    def stats(self) -> Dict[str, int]:
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                counts: Dict[str, int] = {}
                for record in self._records.values():
                    counts[record.state] = counts.get(record.state, 0) + 1
                counts["total"] = len(self._records)
                return counts

    # ─────────────────────── mutations ───────────────────────

    def enqueue(
        self, envelope: TransportEnvelope, *, now_ms: Optional[int] = None
    ) -> OutboxRecord:
        """Register one signed envelope. Idempotent by message_id.

        Already-expired envelopes are rejected (fail closed) instead of
        being parked as dead records.
        """

        now = _validate_operation_time(
            self._clock() if now_ms is None else now_ms, "now_ms"
        )
        ok, reason = validate_envelope(
            envelope,
            now_ms=now,
            require_signature=True,
        )
        if not ok:
            raise TransportEnvelopeRejected(reason)
        envelope_json = canonical_json(envelope.to_dict()).decode("utf-8")
        if len(envelope_json.encode("utf-8")) > MAX_ENVELOPE_BYTES:
            raise TransportEnvelopeRejected("envelope exceeds the wire byte limit")
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                existing = self._records.get(envelope.message_id)
                if existing is not None:
                    if existing.envelope_sha256 != envelope_digest(envelope):
                        raise DeliveryOutboxError(
                            "message_id already bound to different envelope bytes"
                        )
                    return _copy_record(existing)
                pending_count = sum(
                    1 for record in self._records.values() if not record.is_terminal
                )
                if pending_count >= self._max_pending:
                    raise DeliveryOutboxFull(
                        f"outbox holds {pending_count} pending records; cap is "
                        f"{self._max_pending}"
                    )
                record = OutboxRecord(
                    message_id=envelope.message_id,
                    envelope_json=envelope_json,
                    envelope_sha256=envelope_digest(envelope),
                    created_at_ms=envelope.created_at_ms,
                    expires_at_ms=envelope.expires_at_ms,
                )
                self._append_locked(
                    {
                        "event": "enqueued",
                        "message_id": record.message_id,
                        "envelope_json": envelope_json,
                        "envelope_sha256": record.envelope_sha256,
                        "created_at_ms": record.created_at_ms,
                        "expires_at_ms": record.expires_at_ms,
                        "at_ms": now,
                    }
                )
                self._records[record.message_id] = record
                return _copy_record(record)

    def record_attempt(
        self,
        message_id: str,
        *,
        transport: str,
        outcome: str,
        at_ms: Optional[int] = None,
        error_code: str = "",
    ) -> OutboxRecord:
        """Append one delivery attempt outcome for a queued record."""

        _validate_transport_name(transport)
        if outcome not in OUTBOX_ATTEMPT_OUTCOMES:
            raise DeliveryOutboxError(f"unsupported attempt outcome: {outcome}")
        _validate_error_code(error_code)
        now = _validate_operation_time(
            self._clock() if at_ms is None else at_ms, "at_ms"
        )
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                record = self._require_live(message_id)
                if len(record.attempts) >= MAX_ATTEMPTS_PER_RECORD:
                    raise DeliveryOutboxError("attempt history exceeds the cap")
                event: Dict[str, Any] = {
                    "event": "attempt",
                    "message_id": message_id,
                    "transport": transport,
                    "at_ms": now,
                    "outcome": outcome,
                }
                if error_code:
                    event["error_code"] = error_code
                self._append_locked(event)
                record.attempts.append(
                    OutboxAttempt(
                        transport=transport,
                        at_ms=now,
                        outcome=outcome,
                        error_code=error_code,
                    )
                )
                if outcome == OUTBOX_ATTEMPT_REJECTED:
                    record.state = OUTBOX_STATE_REJECTED
                    record.last_error_code = error_code
                else:
                    record.last_error_code = error_code
                return _copy_record(record)

    def handle_ack(self, ack: DeliveryAck, *, now_ms: Optional[int] = None) -> OutboxRecord:
        """Apply one verified ACK: mark delivered, cancel other copies.

        The ACK must carry a valid receiver signature. Matching is by
        ``message_id`` (content address) — a forwarded copy with a different
        hop count legitimately ACKs the same message identity.
        """

        ok, reason = validate_ack(ack, now_ms=now_ms if now_ms is not None else self._clock())
        if not ok:
            raise TransportEnvelopeRejected(f"invalid delivery ack: {reason}")
        now = _validate_operation_time(
            self._clock() if now_ms is None else now_ms, "now_ms"
        )
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                record = self._records.get(ack.message_id)
                if record is None:
                    raise DeliveryOutboxError("ack for unknown message_id")
                envelope = _record_envelope(record)
                if not _ack_digest_matches_envelope(ack.envelope_sha256, envelope):
                    raise DeliveryOutboxError(
                        "ack envelope_sha256 does not match a valid forwarded envelope"
                    )
                if record.state == OUTBOX_STATE_DELIVERED:
                    if ack.receiver_did != record.delivered_by:
                        raise DeliveryOutboxError(
                            "ack receiver does not match the recorded delivery"
                        )
                    return _copy_record(record)
                if record.state != OUTBOX_STATE_QUEUED:
                    raise DeliveryOutboxError(
                        f"cannot acknowledge record in state {record.state}"
                    )
                if envelope.recipient.startswith("did:key:"):
                    if ack.receiver_did != envelope.recipient:
                        raise DeliveryOutboxError(
                            "ack receiver is not the envelope recipient"
                        )
                elif self._authorize_ack is None:
                    raise DeliveryOutboxError(
                        "ack authorization is required for shared recipients"
                    )
                else:
                    try:
                        allowed, authorization_reason = self._authorize_ack(
                            ack, envelope
                        )
                    except Exception as exc:
                        raise DeliveryOutboxError(
                            "ack authorization callback failed"
                        ) from exc
                    if not allowed:
                        raise DeliveryOutboxError(
                            authorization_reason or "ack receiver is not authorized"
                        )
                self._append_locked(
                    {
                        "event": "delivered",
                        "message_id": record.message_id,
                        "at_ms": now,
                        "ack_json": canonical_json(ack.to_dict()).decode("utf-8"),
                    }
                )
                record.state = OUTBOX_STATE_DELIVERED
                record.delivered_by = ack.receiver_did
                record.delivered_at_ms = ack.received_at_ms
                return _copy_record(record)

    def compact(self) -> int:
        """Rewrite the journal keeping only pending records; return kept count.

        Terminal records (delivered/rejected/expired) leave the journal. The
        journal is re-folded from disk first, so records another process
        appended are never dropped. The rewrite is atomic: write a fresh
        journal to a temp file, fsync, then replace, under the cross-process
        lock.
        """

        with self._thread_lock:
            # refold must happen INSIDE the cross-process lock: refolding
            # before acquiring it leaves a window where another process
            # appends a record and our os.replace below silently drops it
            # (round-3 review bug I)
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                keep = [
                    record
                    for record in self._records.values()
                    if not record.is_terminal
                ]
                tmp_path = self._journal_path.with_suffix(".jsonl.tmp")
                with open(tmp_path, "wb") as handle:
                    for record in keep:
                        handle.write(canonical_json(
                            {
                                "event": "enqueued",
                                "message_id": record.message_id,
                                "envelope_json": record.envelope_json,
                                "envelope_sha256": record.envelope_sha256,
                                "created_at_ms": record.created_at_ms,
                                "expires_at_ms": record.expires_at_ms,
                                "at_ms": record.created_at_ms,
                            }
                        ) + b"\n")
                        for attempt in record.attempts:
                            event: Dict[str, Any] = {
                                "event": "attempt",
                                "message_id": record.message_id,
                                "transport": attempt.transport,
                                "at_ms": attempt.at_ms,
                                "outcome": attempt.outcome,
                            }
                            if attempt.error_code:
                                event["error_code"] = attempt.error_code
                            handle.write(canonical_json(event) + b"\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, self._journal_path)
                # fingerprint captured INSIDE the lock (round-4 bug Q)
                try:
                    stat = os.stat(self._journal_path)
                    self._journal_stat = (stat.st_mtime_ns, stat.st_size)
                except OSError:  # pragma: no cover - stat after our own replace
                    pass
            self._records = {record.message_id: record for record in keep}
            return len(keep)

    # ─────────────────────── internals ───────────────────────

    def _require_live(self, message_id: str) -> OutboxRecord:
        record = self._records.get(message_id)
        if record is None:
            raise DeliveryOutboxError("outbox record missing")
        if record.state == OUTBOX_STATE_DELIVERED:
            raise DeliveryOutboxError("record is already delivered")
        if record.state == OUTBOX_STATE_REJECTED:
            raise DeliveryOutboxError("record is terminally rejected")
        if record.state == OUTBOX_STATE_EXPIRED:
            raise DeliveryOutboxError("record is expired")
        return record

    def _transition_expired(self, record: OutboxRecord, now_ms: int) -> None:
        self._append_locked(
            {
                "event": "expired",
                "message_id": record.message_id,
                "at_ms": now_ms,
            }
        )
        record.state = OUTBOX_STATE_EXPIRED


def _fold_event(records: Dict[str, OutboxRecord], event: Dict[str, Any]) -> None:
    """Apply one journal event to the fold. Unknown shapes fail closed."""

    kind = event.get("event")
    if kind not in _JOURNAL_EVENTS:
        raise DeliveryOutboxCorrupt(f"unknown journal event: {kind!r}")
    allowed_fields = _EVENT_FIELDS[kind]
    fields = frozenset(event)
    if kind == "attempt":
        if not allowed_fields <= fields or not fields <= allowed_fields | {"error_code"}:
            raise DeliveryOutboxCorrupt("attempt event has missing or unknown fields")
    elif fields != allowed_fields:
        raise DeliveryOutboxCorrupt(
            f"{kind} event has missing or unknown fields"
        )
    message_id = event.get("message_id")
    if not isinstance(message_id, str) or _MESSAGE_ID_RE.fullmatch(message_id) is None:
        raise DeliveryOutboxCorrupt("journal event message_id is not a content address")

    if kind == "enqueued":
        if message_id in records:
            raise DeliveryOutboxCorrupt("duplicate enqueued event for message_id")
        envelope_json = event.get("envelope_json")
        envelope_sha256 = event.get("envelope_sha256")
        created_at_ms = event.get("created_at_ms")
        expires_at_ms = event.get("expires_at_ms")
        if not isinstance(envelope_json, str) or not envelope_json:
            raise DeliveryOutboxCorrupt("enqueued event missing envelope_json")
        if not isinstance(envelope_sha256, str) or _MESSAGE_ID_RE.fullmatch(envelope_sha256) is None:
            raise DeliveryOutboxCorrupt("enqueued event missing envelope_sha256")
        for value in (created_at_ms, expires_at_ms):
            if isinstance(value, bool) or not isinstance(value, int):
                raise DeliveryOutboxCorrupt("enqueued event timestamps must be integers")
        _fold_at_ms(event)
        assert isinstance(created_at_ms, int)
        assert isinstance(expires_at_ms, int)
        enqueued_record = OutboxRecord(
            message_id=message_id,
            envelope_json=envelope_json,
            envelope_sha256=envelope_sha256,
            created_at_ms=created_at_ms,
            expires_at_ms=expires_at_ms,
        )
        _record_envelope(enqueued_record)
        records[message_id] = enqueued_record
        return

    record = records.get(message_id)
    if record is None:
        raise DeliveryOutboxCorrupt(f"journal event for unknown message_id: {kind}")

    if kind == "attempt":
        if record.state != OUTBOX_STATE_QUEUED:
            raise DeliveryOutboxCorrupt("attempt event follows a terminal state")
        if len(record.attempts) >= MAX_ATTEMPTS_PER_RECORD:
            raise DeliveryOutboxCorrupt("attempt history exceeds the cap")
        transport = _fold_transport(event)
        outcome = event.get("outcome")
        if outcome not in OUTBOX_ATTEMPT_OUTCOMES:
            raise DeliveryOutboxCorrupt(f"unsupported attempt outcome: {outcome!r}")
        at_ms = _fold_at_ms(event)
        error_code = event.get("error_code", "")
        try:
            validated_error_code = _validate_error_code(error_code)
        except DeliveryOutboxError as exc:
            raise DeliveryOutboxCorrupt(str(exc)) from exc
        record.attempts.append(
            OutboxAttempt(
                transport=transport,
                at_ms=at_ms,
                outcome=outcome,
                error_code=validated_error_code,
            )
        )
        if outcome == OUTBOX_ATTEMPT_REJECTED and record.state == OUTBOX_STATE_QUEUED:
            record.state = OUTBOX_STATE_REJECTED
        if validated_error_code:
            record.last_error_code = validated_error_code
        return

    if record.state in OUTBOX_TERMINAL_STATES:
        raise DeliveryOutboxCorrupt(f"{kind} event follows a terminal state")

    at_ms = _fold_at_ms(event)
    if kind == "delivered":
        ack_json = event.get("ack_json")
        if not isinstance(ack_json, str):
            raise DeliveryOutboxCorrupt("delivered event ack_json must be text")
        try:
            ack = DeliveryAck.from_dict(json.loads(ack_json))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise DeliveryOutboxCorrupt(f"delivered event ACK is invalid: {exc}") from exc
        if canonical_json(ack.to_dict()).decode("utf-8") != ack_json:
            raise DeliveryOutboxCorrupt("delivered event ACK is not canonical JSON")
        ok, reason = validate_ack(ack, now_ms=at_ms)
        if not ok:
            raise DeliveryOutboxCorrupt(f"delivered event ACK is invalid: {reason}")
        envelope = _record_envelope(record)
        if ack.message_id != message_id or not _ack_digest_matches_envelope(
            ack.envelope_sha256, envelope
        ):
            raise DeliveryOutboxCorrupt("delivered event ACK binding mismatch")
        if (
            envelope.recipient.startswith("did:key:")
            and ack.receiver_did != envelope.recipient
        ):
            raise DeliveryOutboxCorrupt("delivered event ACK receiver mismatch")
        record.state = OUTBOX_STATE_DELIVERED
        record.delivered_by = ack.receiver_did
        record.delivered_at_ms = ack.received_at_ms
        return
    if kind == "rejected":
        transport = _fold_transport(event)
        error_code = event.get("error_code")
        try:
            validated_error_code = _validate_error_code(error_code)
        except DeliveryOutboxError as exc:
            raise DeliveryOutboxCorrupt(str(exc)) from exc
        record.state = OUTBOX_STATE_REJECTED
        record.last_error_code = validated_error_code
        return
    if kind == "expired":
        record.state = OUTBOX_STATE_EXPIRED
        return
    raise DeliveryOutboxCorrupt(f"unhandled journal event: {kind}")  # pragma: no cover


def _fold_transport(event: Mapping[str, Any]) -> str:
    transport = event.get("transport")
    if not isinstance(transport, str) or _TRANSPORT_NAME_RE.fullmatch(transport) is None:
        raise DeliveryOutboxCorrupt("journal event transport name is invalid")
    return transport


def _fold_at_ms(event: Mapping[str, Any]) -> int:
    at_ms = event.get("at_ms")
    if isinstance(at_ms, bool) or not isinstance(at_ms, int) or at_ms < 0:
        raise DeliveryOutboxCorrupt("journal event at_ms must be a non-negative integer")
    return at_ms


def _copy_record(record: OutboxRecord) -> OutboxRecord:
    return OutboxRecord(
        message_id=record.message_id,
        envelope_json=record.envelope_json,
        envelope_sha256=record.envelope_sha256,
        created_at_ms=record.created_at_ms,
        expires_at_ms=record.expires_at_ms,
        state=record.state,
        attempts=list(record.attempts),
        delivered_by=record.delivered_by,
        delivered_at_ms=record.delivered_at_ms,
        last_error_code=record.last_error_code,
    )


def _ack_digest_matches_envelope(
    acknowledged_digest: str,
    envelope: TransportEnvelope,
) -> bool:
    """Accept only origin bytes or a valid hop-count-only forwarded copy."""

    start_hop = envelope.routing["hop_count"]
    hop_limit = envelope.routing["hop_limit"]
    for hop_count in range(start_hop, hop_limit + 1):
        candidate = envelope.to_dict()
        candidate["routing"]["hop_count"] = hop_count
        if envelope_digest(candidate) == acknowledged_digest:
            return True
    return False


def _record_envelope(record: OutboxRecord) -> TransportEnvelope:
    """Reconstruct and verify the envelope bound into an outbox record."""

    try:
        parsed = json.loads(record.envelope_json)
        envelope = TransportEnvelope.from_dict(parsed)
        if canonical_json(envelope.to_dict()).decode("utf-8") != record.envelope_json:
            raise DeliveryOutboxCorrupt("enqueued envelope_json is not canonical")
        ok, reason = validate_envelope(envelope, require_signature=True)
        if not ok:
            raise DeliveryOutboxCorrupt(f"enqueued envelope is invalid: {reason}")
        if envelope.message_id != record.message_id:
            raise DeliveryOutboxCorrupt("enqueued message_id does not match envelope")
        if envelope_digest(envelope) != record.envelope_sha256:
            raise DeliveryOutboxCorrupt("enqueued envelope_sha256 does not match envelope")
        if (
            envelope.created_at_ms != record.created_at_ms
            or envelope.expires_at_ms != record.expires_at_ms
        ):
            raise DeliveryOutboxCorrupt("enqueued timestamps do not match envelope")
        return envelope
    except DeliveryOutboxCorrupt:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, UnicodeError) as exc:
        raise DeliveryOutboxCorrupt(f"enqueued envelope_json is invalid: {exc}") from exc
