"""Tests for nth_dao.delivery.outbox — durable, crash-safe outbox.

Covers the design-doc §12.1 requirements: enqueue idempotency, ACK-terminal
delivery, sibling-copy cancellation, expiry, capacity fail-closed, journal
crash recovery (torn tail tolerated, mid-file corruption loud), compaction,
and cross-process lock safety.
"""

from __future__ import annotations

import json

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import (
    envelope_digest,
    forward_envelope,
    sign_envelope,
)
from nth_dao.delivery.outbox import (
    DEFAULT_MAX_PENDING_RECORDS,
    OUTBOX_STATE_DELIVERED,
    OUTBOX_STATE_QUEUED,
    OUTBOX_STATE_REJECTED,
    DeliveryOutboxCorrupt,
    DeliveryOutboxError,
    DeliveryOutboxFull,
    DurableOutbox,
)

pytest.importorskip("nacl")

NOW_MS = 1_750_000_000_000


@pytest.fixture()
def alice_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def bob_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="bob")


def _envelope(
    alice_identity,
    payload=None,
    ttl_ms=60_000,
    created_at_ms=NOW_MS,
    hop_limit=0,
    recipient="dao:core",
):
    return sign_envelope(
        alice_identity,
        kind="mission.announcement",
        recipient=recipient,
        payload={"n": 1} if payload is None else payload,
        created_at_ms=created_at_ms,
        expires_at_ms=created_at_ms + ttl_ms,
        hop_limit=hop_limit,
    )


@pytest.fixture()
def outbox(tmp_path):
    return DurableOutbox(tmp_path / "delivery", clock=lambda: NOW_MS)


class TestEnqueue:
    def test_enqueue_and_get(self, outbox, alice_identity):
        envelope = _envelope(alice_identity)
        record = outbox.enqueue(envelope)
        assert record.state == OUTBOX_STATE_QUEUED
        assert record.message_id == envelope.message_id
        assert record.envelope_sha256 == envelope_digest(envelope)
        assert outbox.get(envelope.message_id).envelope_json == record.envelope_json

    def test_enqueue_is_idempotent(self, outbox, alice_identity):
        envelope = _envelope(alice_identity)
        first = outbox.enqueue(envelope)
        second = outbox.enqueue(envelope)
        assert first.message_id == second.message_id
        assert len(outbox.stats().keys()) >= 1
        assert outbox.stats()["queued"] == 1

    def test_enqueue_same_id_different_bytes_rejected(self, outbox, alice_identity):
        """A forwarded copy (hop_count=1) carries the same message identity
        but different wire bytes — the outbox binds one record to the exact
        origin bytes and fails closed on the collision."""

        envelope = _envelope(alice_identity, hop_limit=2)
        outbox.enqueue(envelope)
        forwarded = forward_envelope(envelope)
        assert forwarded.message_id == envelope.message_id
        with pytest.raises(DeliveryOutboxError, match="different envelope bytes"):
            outbox.enqueue(forwarded)

    def test_enqueue_unsigned_rejected(self, outbox, alice_identity):
        envelope = _envelope(alice_identity)
        envelope.signature = ""
        with pytest.raises(Exception, match="signature"):
            outbox.enqueue(envelope)

    def test_capacity_fail_closed(self, tmp_path, alice_identity):
        outbox = DurableOutbox(
            tmp_path / "delivery", max_pending_records=2, clock=lambda: NOW_MS
        )
        outbox.enqueue(_envelope(alice_identity, payload={"n": 1}))
        outbox.enqueue(_envelope(alice_identity, payload={"n": 2}))
        with pytest.raises(DeliveryOutboxFull):
            outbox.enqueue(_envelope(alice_identity, payload={"n": 3}))

    def test_default_cap_is_design_constant(self):
        assert DEFAULT_MAX_PENDING_RECORDS == 4_096


class TestAttemptsAndTerminalStates:
    @pytest.mark.parametrize("value", [True, 0, -1, 1.5])
    def test_operation_times_are_strict_positive_integers(
        self, outbox, alice_identity, value
    ):
        envelope = _envelope(alice_identity)
        if value is True:
            with pytest.raises(DeliveryOutboxError, match="now_ms"):
                outbox.enqueue(envelope, now_ms=value)
            outbox.enqueue(envelope)
        else:
            outbox.enqueue(envelope)
        with pytest.raises(DeliveryOutboxError, match="at_ms"):
            outbox.record_attempt(
                envelope.message_id,
                transport="loopback",
                outcome="sent",
                at_ms=value,
            )

    def test_error_code_is_bounded(self, outbox, alice_identity):
        envelope = _envelope(alice_identity)
        outbox.enqueue(envelope)
        with pytest.raises(DeliveryOutboxError, match="error_code"):
            outbox.record_attempt(
                envelope.message_id,
                transport="loopback",
                outcome="error",
                error_code="x" * 257,
            )

    def test_attempt_sent_recorded(self, outbox, alice_identity):
        envelope = _envelope(alice_identity)
        outbox.enqueue(envelope)
        record = outbox.record_attempt(
            envelope.message_id, transport="loopback", outcome="sent", at_ms=NOW_MS + 10
        )
        assert len(record.attempts) == 1
        assert record.attempts[0].transport == "loopback"
        assert record.state == OUTBOX_STATE_QUEUED

    def test_attempt_rejected_is_terminal(self, outbox, alice_identity):
        envelope = _envelope(alice_identity)
        outbox.enqueue(envelope)
        record = outbox.record_attempt(
            envelope.message_id,
            transport="loopback",
            outcome="rejected",
            error_code="target-policy-rejected",
            at_ms=NOW_MS + 10,
        )
        assert record.state == OUTBOX_STATE_REJECTED
        assert record.last_error_code == "target-policy-rejected"
        with pytest.raises(DeliveryOutboxError, match="terminally rejected"):
            outbox.record_attempt(
                envelope.message_id, transport="loopback", outcome="sent"
            )

    def test_unknown_outcome_rejected(self, outbox, alice_identity):
        envelope = _envelope(alice_identity)
        outbox.enqueue(envelope)
        with pytest.raises(DeliveryOutboxError, match="outcome"):
            outbox.record_attempt(
                envelope.message_id, transport="loopback", outcome="maybe"
            )

    def test_bad_transport_name_rejected(self, outbox, alice_identity):
        envelope = _envelope(alice_identity)
        outbox.enqueue(envelope)
        with pytest.raises(DeliveryOutboxError, match="transport name"):
            outbox.record_attempt(
                envelope.message_id, transport="../evil", outcome="sent"
            )

    def test_attempt_unknown_message_rejected(self, outbox):
        with pytest.raises(DeliveryOutboxError, match="missing"):
            outbox.record_attempt("sha256:" + "0" * 64, transport="loopback", outcome="sent")


class TestAckDelivery:
    def test_valid_ack_marks_delivered(self, outbox, alice_identity, bob_identity):
        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        outbox.record_attempt(
            envelope.message_id, transport="loopback", outcome="sent", at_ms=NOW_MS + 5
        )
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 20,
        )
        record = outbox.handle_ack(ack, now_ms=NOW_MS + 25)
        assert record.state == OUTBOX_STATE_DELIVERED
        assert record.delivered_by == bob_identity.as_did()
        assert outbox.stats()["delivered"] == 1

    def test_ack_cancels_pending_state(self, outbox, alice_identity, bob_identity):
        """One ACK removes the message from pending even though several
        transport copies were attempted — the 'cancel the rest' rule."""

        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        for transport in ("loopback", "file_bundle"):
            outbox.record_attempt(
                envelope.message_id, transport=transport, outcome="sent", at_ms=NOW_MS
            )
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 10,
        )
        outbox.handle_ack(ack, now_ms=NOW_MS + 15)
        assert outbox.pending(now_ms=NOW_MS + 20) == []

    def test_ack_is_idempotent(self, outbox, alice_identity, bob_identity):
        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        outbox.handle_ack(ack, now_ms=NOW_MS)
        again = outbox.handle_ack(ack, now_ms=NOW_MS)
        assert again.state == OUTBOX_STATE_DELIVERED
        assert outbox.stats()["delivered"] == 1

    def test_valid_signature_from_wrong_receiver_rejected(
        self, outbox, alice_identity, bob_identity
    ):
        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        ack = sign_ack(
            alice_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        with pytest.raises(DeliveryOutboxError, match="not the envelope recipient"):
            outbox.handle_ack(ack, now_ms=NOW_MS)
        assert outbox.get(envelope.message_id).state == OUTBOX_STATE_QUEUED

    def test_valid_signature_for_wrong_envelope_digest_rejected(
        self, outbox, alice_identity, bob_identity
    ):
        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256="sha256:" + "0" * 64,
            received_at_ms=NOW_MS,
        )
        with pytest.raises(DeliveryOutboxError, match="does not match"):
            outbox.handle_ack(ack, now_ms=NOW_MS)
        assert outbox.get(envelope.message_id).state == OUTBOX_STATE_QUEUED

    def test_shared_recipient_ack_requires_explicit_authorization(
        self, tmp_path, alice_identity, bob_identity
    ):
        envelope = _envelope(alice_identity)
        denied = DurableOutbox(tmp_path / "denied", clock=lambda: NOW_MS)
        denied.enqueue(envelope)
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        with pytest.raises(DeliveryOutboxError, match="authorization is required"):
            denied.handle_ack(ack, now_ms=NOW_MS)

        allowed = DurableOutbox(
            tmp_path / "allowed",
            clock=lambda: NOW_MS,
            authorize_ack=lambda candidate, queued: (
                candidate.receiver_did == bob_identity.as_did()
                and queued.recipient == "dao:core",
                "not a current DAO member",
            ),
        )
        allowed.enqueue(envelope)
        assert allowed.handle_ack(ack, now_ms=NOW_MS).state == OUTBOX_STATE_DELIVERED

    def test_forged_ack_rejected(self, outbox, alice_identity, bob_identity):
        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        ack.receiver_did = alice_identity.as_did()  # claims alice signed it — she did not
        with pytest.raises(Exception, match="invalid delivery ack"):
            outbox.handle_ack(ack, now_ms=NOW_MS)

    def test_ack_unknown_message_rejected(self, outbox, bob_identity):
        ack = sign_ack(
            bob_identity,
            message_id="sha256:" + "1" * 64,
            envelope_sha256="sha256:" + "2" * 64,
            received_at_ms=NOW_MS,
        )
        with pytest.raises(DeliveryOutboxError, match="unknown message_id"):
            outbox.handle_ack(ack, now_ms=NOW_MS)

    def test_ack_after_expiry_rejected(self, tmp_path, alice_identity, bob_identity):
        outbox = DurableOutbox(tmp_path / "delivery", clock=lambda: NOW_MS)
        envelope = _envelope(
            alice_identity, ttl_ms=1_000, recipient=bob_identity.as_did()
        )
        outbox.enqueue(envelope)
        assert outbox.pending(now_ms=NOW_MS + 2_000) == []
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 2_100,
        )
        with pytest.raises(DeliveryOutboxError, match="expired"):
            outbox.handle_ack(ack, now_ms=NOW_MS + 2_100)


class TestExpiry:
    def test_pending_folds_expired(self, outbox, alice_identity):
        envelope = _envelope(alice_identity, ttl_ms=1_000)
        outbox.enqueue(envelope)
        assert len(outbox.pending(now_ms=NOW_MS)) == 1
        assert outbox.pending(now_ms=NOW_MS + 1_001) == []
        assert outbox.stats()["expired"] == 1


class TestCrashRecovery:
    def test_reload_folds_journal(self, tmp_path, alice_identity, bob_identity):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        outbox.record_attempt(
            envelope.message_id, transport="loopback", outcome="sent", at_ms=NOW_MS + 5
        )
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 10,
        )
        outbox.handle_ack(ack, now_ms=NOW_MS + 15)

        reloaded = DurableOutbox(directory, clock=lambda: NOW_MS + 100)
        record = reloaded.get(envelope.message_id)
        assert record is not None
        assert record.state == OUTBOX_STATE_DELIVERED
        assert record.delivered_by == bob_identity.as_did()
        assert len(record.attempts) == 1

    def test_torn_final_line_ignored(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        outbox.enqueue(_envelope(alice_identity, payload={"n": 1}))
        journal = directory / "outbox.journal.jsonl"
        # simulate a crash mid-append: partial line without newline
        with open(journal, "ab") as handle:
            handle.write(b'{"event":"enque')
        reloaded = DurableOutbox(directory, clock=lambda: NOW_MS)
        assert reloaded.stats()["queued"] == 1

    def test_midfile_corruption_fails_closed(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        outbox.enqueue(_envelope(alice_identity, payload={"n": 1}))
        outbox.enqueue(_envelope(alice_identity, payload={"n": 2}))
        journal = directory / "outbox.journal.jsonl"
        lines = journal.read_bytes().split(b"\n")
        lines[0] = b"{corrupt"
        journal.write_bytes(b"\n".join(lines))
        with pytest.raises(DeliveryOutboxCorrupt):
            DurableOutbox(directory, clock=lambda: NOW_MS)

    def test_unknown_journal_fields_fail_closed(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        outbox.enqueue(_envelope(alice_identity))
        journal = directory / "outbox.journal.jsonl"
        event = json.loads(journal.read_text().splitlines()[0])
        event["ignored_by_old_fold"] = True
        journal.write_bytes(canonical_json(event) + b"\n")

        with pytest.raises(DeliveryOutboxCorrupt, match="unknown fields"):
            DurableOutbox(directory, clock=lambda: NOW_MS)

    def test_persisted_ack_is_reverified(
        self, tmp_path, alice_identity, bob_identity
    ):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        outbox.handle_ack(ack, now_ms=NOW_MS)

        journal = directory / "outbox.journal.jsonl"
        events = [json.loads(line) for line in journal.read_text().splitlines()]
        persisted_ack = json.loads(events[-1]["ack_json"])
        persisted_ack["receiver_did"] = alice_identity.as_did()
        events[-1]["ack_json"] = canonical_json(persisted_ack).decode("utf-8")
        journal.write_bytes(b"".join(canonical_json(event) + b"\n" for event in events))

        with pytest.raises(DeliveryOutboxCorrupt, match="ACK is invalid"):
            DurableOutbox(directory, clock=lambda: NOW_MS)

    def test_recovered_outbox_still_dispatchable(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        outbox.enqueue(envelope)
        reloaded = DurableOutbox(directory, clock=lambda: NOW_MS)
        pending = reloaded.pending(now_ms=NOW_MS + 100)
        assert len(pending) == 1
        assert pending[0].message_id == envelope.message_id


class TestCompaction:
    def test_compact_keeps_pending_only(self, tmp_path, alice_identity, bob_identity):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        delivered = _envelope(
            alice_identity, payload={"n": 1}, recipient=bob_identity.as_did()
        )
        queued = _envelope(alice_identity, payload={"n": 2})
        outbox.enqueue(delivered)
        outbox.enqueue(queued)
        ack = sign_ack(
            bob_identity,
            message_id=delivered.message_id,
            envelope_sha256=envelope_digest(delivered),
            received_at_ms=NOW_MS,
        )
        outbox.handle_ack(ack, now_ms=NOW_MS)
        kept = outbox.compact()
        assert kept == 1
        reloaded = DurableOutbox(directory, clock=lambda: NOW_MS)
        assert reloaded.get(delivered.message_id) is None
        assert reloaded.get(queued.message_id).state == OUTBOX_STATE_QUEUED

    def test_compact_preserves_attempt_history(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        outbox.enqueue(envelope)
        outbox.record_attempt(
            envelope.message_id, transport="loopback", outcome="error", error_code="peer-network-error"
        )
        outbox.compact()
        reloaded = DurableOutbox(directory, clock=lambda: NOW_MS)
        record = reloaded.get(envelope.message_id)
        assert len(record.attempts) == 1
        assert record.attempts[0].error_code == "peer-network-error"
        assert record.last_error_code == "peer-network-error"


class TestCrossProcess:
    def test_two_instances_share_journal(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        first = DurableOutbox(directory, clock=lambda: NOW_MS)
        second = DurableOutbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        first.enqueue(envelope)
        second.enqueue(envelope)  # idempotent through its own fold of the shared journal
        assert first.stats()["queued"] == 1
        assert second.stats()["queued"] == 1

    def test_concurrent_instances_enqueue_one_journal_record(
        self, tmp_path, alice_identity
    ):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier

        directory = tmp_path / "delivery"
        outboxes = [
            DurableOutbox(directory, clock=lambda: NOW_MS),
            DurableOutbox(directory, clock=lambda: NOW_MS),
        ]
        envelope = _envelope(alice_identity)
        barrier = Barrier(2)

        def enqueue(index):
            barrier.wait(timeout=5)
            return outboxes[index].enqueue(envelope)

        with ThreadPoolExecutor(max_workers=2) as pool:
            records = list(pool.map(enqueue, range(2)))

        assert {record.message_id for record in records} == {envelope.message_id}
        journal = directory / "outbox.journal.jsonl"
        events = [json.loads(line) for line in journal.read_text().splitlines() if line]
        assert sum(event["event"] == "enqueued" for event in events) == 1

    def test_journal_lines_are_valid_json_objects(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        outbox.enqueue(envelope)
        outbox.record_attempt(envelope.message_id, transport="loopback", outcome="sent")
        journal = directory / "outbox.journal.jsonl"
        events = [json.loads(line) for line in journal.read_text().splitlines() if line]
        assert events[0]["event"] == "enqueued"
        assert events[1]["event"] == "attempt"
        assert events[1]["transport"] == "loopback"


# ─────────────────── adversarial review round 2 (bugs B + C) ───────────────────


class TestReviewRoundTwo:
    def test_attempt_on_delivered_record_rejected(self, outbox, alice_identity, bob_identity):
        """Bug B: a transport attempt arriving AFTER the signed ACK must be
        rejected instead of silently appending to a delivered record."""

        envelope = _envelope(alice_identity, recipient=bob_identity.as_did())
        outbox.enqueue(envelope)
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        outbox.handle_ack(ack, now_ms=NOW_MS)
        with pytest.raises(DeliveryOutboxError, match="already delivered"):
            outbox.record_attempt(
                envelope.message_id, transport="loopback", outcome="sent"
            )

    def test_compact_never_drops_other_process_records(self, tmp_path, alice_identity):
        """Bug C: instance A compacting must first re-fold the journal so
        records process B enqueued survive (previously: data loss)."""

        directory = tmp_path / "delivery"
        proc_a = DurableOutbox(directory, clock=lambda: NOW_MS)
        proc_b = DurableOutbox(directory, clock=lambda: NOW_MS)
        env_a = _envelope(alice_identity, payload={"n": 1})
        env_b = _envelope(alice_identity, payload={"n": 2})
        proc_a.enqueue(env_a)
        proc_b.enqueue(env_b)

        kept = proc_a.compact()

        reloaded = DurableOutbox(directory, clock=lambda: NOW_MS)
        assert kept == 2
        assert reloaded.get(env_a.message_id) is not None
        assert reloaded.get(env_b.message_id) is not None
        assert reloaded.stats()["queued"] == 2

    def test_cross_process_enqueue_is_idempotent_via_refold(self, tmp_path, alice_identity):
        """Bug C follow-up: two processes enqueuing the same message_id must
        converge to ONE record (journal holds a single enqueued event)."""

        import json as jsonlib

        directory = tmp_path / "delivery"
        proc_a = DurableOutbox(directory, clock=lambda: NOW_MS)
        proc_b = DurableOutbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        first = proc_a.enqueue(envelope)
        second = proc_b.enqueue(envelope)
        assert first.message_id == second.message_id
        journal = directory / "outbox.journal.jsonl"
        events = [jsonlib.loads(line) for line in journal.read_text().splitlines() if line]
        enqueued = [e for e in events if e["event"] == "enqueued" and e["message_id"] == envelope.message_id]
        assert len(enqueued) == 1
        reloaded = DurableOutbox(directory, clock=lambda: NOW_MS)
        assert reloaded.stats()["queued"] == 1

    def test_live_refold_sees_other_process_expiry(self, tmp_path, alice_identity):
        """Process A's pending() must reflect process B's state changes
        without restart (mtime/size based re-fold)."""

        directory = tmp_path / "delivery"
        proc_a = DurableOutbox(directory, clock=lambda: NOW_MS)
        proc_b = DurableOutbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity, ttl_ms=1_000)
        proc_a.enqueue(envelope)
        # process B observes the expiry first (its own fold sees the journal)
        assert proc_b.pending(now_ms=NOW_MS + 2_000) == []
        # process A re-folds and agrees
        assert proc_a.pending(now_ms=NOW_MS + 2_000) == []
        assert proc_a.stats()["expired"] == 1


# ─────────────────── adversarial review round 3 (bug I) ───────────────────


class TestCompactLockOrder:
    def test_refold_happens_inside_cross_process_lock(self, tmp_path, monkeypatch):
        """Bug I: compact() must re-fold while HOLDING the cross-process
        lock. Refolding before the lock leaves a window where another
        process appends and our os.replace silently drops it."""

        import nth_dao.delivery.outbox as outbox_module

        directory = tmp_path / "delivery"
        outbox = DurableOutbox(directory, clock=lambda: NOW_MS)

        events = []

        class RecordingLock:
            def __init__(self, path):
                pass

            def __enter__(self):
                events.append("lock")
                return self

            def __exit__(self, *args):
                events.append("unlock")
                return False

        monkeypatch.setattr(outbox_module, "InterProcessLock", RecordingLock)
        orig_refold = outbox._refold_if_changed.__get__(outbox)

        def spy_refold():
            events.append("refold")
            orig_refold()

        monkeypatch.setattr(outbox, "_refold_if_changed", spy_refold)
        outbox.compact()
        monkeypatch.undo()
        assert events == ["lock", "refold", "unlock"]

    def test_foreign_append_during_compact_window_survives(self, tmp_path, alice_identity):
        """End-to-end pin for bug I: a record appended to the journal right
        before compact() — while our view is stale — must survive."""

        import json as jsonlib

        directory = tmp_path / "delivery"
        proc_a = DurableOutbox(directory, clock=lambda: NOW_MS)
        env_a = _envelope(alice_identity, payload={"n": 1})
        proc_a.enqueue(env_a)

        # process B appends a record without proc_a knowing (stale stat)
        journal = directory / "outbox.journal.jsonl"
        env_b = _envelope(alice_identity, payload={"n": 2})
        foreign_line = jsonlib.dumps({
            "event": "enqueued",
            "message_id": env_b.message_id,
            "envelope_json": jsonlib.dumps(env_b.to_dict(), sort_keys=True, separators=(",", ":")),
            "envelope_sha256": envelope_digest(env_b),
            "created_at_ms": env_b.created_at_ms,
            "expires_at_ms": env_b.expires_at_ms,
            "at_ms": NOW_MS,
        })
        # wait for proc_a's stat to settle, then write behind its back
        import time as time_mod

        time_mod.sleep(0.02)
        with open(journal, "ab") as handle:
            handle.write(foreign_line.encode("utf-8") + b"\n")

        proc_a.compact()

        reloaded = DurableOutbox(directory, clock=lambda: NOW_MS)
        assert reloaded.get(env_b.message_id) is not None
        assert reloaded.get(env_a.message_id) is not None


# ─────────────────── adversarial review round 4 (bug Q) ───────────────────


class TestFingerprintUnderLock:
    def test_append_fingerprint_captured_while_holding_lock(self, tmp_path, alice_identity, monkeypatch):
        """Bug Q: the journal fingerprint must be sampled while STILL holding
        the cross-process lock — one taken after release could absorb another
        process's append and hide it from the re-fold check forever."""

        import nth_dao.delivery.outbox as outbox_module

        outbox = DurableOutbox(tmp_path / "delivery", clock=lambda: NOW_MS)
        events = []

        class RecordingLock:
            def __init__(self, path):
                pass

            def __enter__(self):
                events.append("lock")
                return self

            def __exit__(self, *args):
                events.append("unlock")
                return False

        monkeypatch.setattr(outbox_module, "InterProcessLock", RecordingLock)
        real_fstat = outbox_module.os.fstat

        def spy_fstat(fd):
            events.append("fstat")
            return real_fstat(fd)

        monkeypatch.setattr(outbox_module.os, "fstat", spy_fstat)

        outbox.enqueue(_envelope(alice_identity))

        assert events == ["lock", "fstat", "unlock"]

    def test_fingerprint_matches_disk_after_append(self, tmp_path, alice_identity):
        outbox = DurableOutbox(tmp_path / "delivery", clock=lambda: NOW_MS)
        outbox.enqueue(_envelope(alice_identity))
        journal = tmp_path / "delivery" / "outbox.journal.jsonl"
        stat = journal.stat()
        assert outbox._journal_stat == (stat.st_mtime_ns, stat.st_size)
