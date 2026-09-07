"""Tests for nth_dao.delivery.inbox — the fail-closed receive pipeline."""

from __future__ import annotations

import json

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    TransportEnvelope,
    envelope_digest,
    forward_envelope,
    sign_envelope,
)
from nth_dao.delivery.inbox import (
    DeliveryInbox,
    DeliveryInboxCacheCorrupt,
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


@pytest.fixture()
def inbox(tmp_path):
    return DeliveryInbox(tmp_path / "delivery", clock=lambda: NOW_MS + 1_000)


def _envelope(alice_identity, payload=None, ttl_ms=60_000, hop_limit=0):
    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient="dao:core",
        payload={"body": "hi"} if payload is None else payload,
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + ttl_ms,
        hop_limit=hop_limit,
    )


def _wire(envelope):
    return canonical_json(envelope.to_dict()).decode("utf-8")


class TestAccept:
    def test_accepts_valid_wire_envelope(self, inbox, alice_identity):
        envelope = _envelope(alice_identity)
        decision = inbox.accept(_wire(envelope), now_ms=NOW_MS + 1_000)
        assert decision.accepted, decision.reason
        assert decision.message_id == envelope.message_id
        assert decision.envelope_sha256 == envelope_digest(envelope)
        assert inbox.seen(envelope.message_id)

    def test_accepts_envelope_object(self, inbox, alice_identity):
        envelope = _envelope(alice_identity)
        decision = inbox.accept(envelope, now_ms=NOW_MS + 1_000)
        assert decision.accepted, decision.reason

    def test_duplicate_is_idempotent_drop(self, inbox, alice_identity):
        envelope = _envelope(alice_identity)
        first = inbox.accept(_wire(envelope), now_ms=NOW_MS + 1_000)
        second = inbox.accept(_wire(envelope), now_ms=NOW_MS + 2_000)
        assert first.accepted
        assert not second.accepted
        assert second.duplicate
        assert second.reason == "duplicate"
        assert inbox.entry_count() == 1

    def test_forwarded_copy_is_same_identity(self, inbox, alice_identity):
        """hop_count differs on the wire but the content address is the same:
        the inbox must treat the forwarded copy as the same message."""

        envelope = _envelope(alice_identity, hop_limit=2)
        forwarded = forward_envelope(envelope)
        assert inbox.accept(_wire(envelope), now_ms=NOW_MS + 1_000).accepted
        decision = inbox.accept(_wire(forwarded), now_ms=NOW_MS + 1_500)
        assert not decision.accepted and decision.duplicate

    def test_replay_same_nonce_rejected(self, inbox, alice_identity):
        envelope = _envelope(alice_identity, payload={"n": 1})
        assert inbox.accept(_wire(envelope), now_ms=NOW_MS + 1_000).accepted
        replay = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"n": 2},  # different content, same nonce
            created_at_ms=NOW_MS + 500,
            expires_at_ms=NOW_MS + 61_000,
            nonce=envelope.nonce,
        )
        decision = inbox.accept(_wire(replay), now_ms=NOW_MS + 1_500)
        assert not decision.accepted
        assert decision.replayed
        assert decision.reason == "replayed nonce"

    def test_replay_cache_survives_restart(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        first = DeliveryInbox(directory, clock=lambda: NOW_MS + 1_000)
        envelope = _envelope(alice_identity)
        assert first.accept(_wire(envelope), now_ms=NOW_MS + 1_000).accepted

        reloaded = DeliveryInbox(directory, clock=lambda: NOW_MS + 2_000)
        assert reloaded.seen(envelope.message_id)
        again = reloaded.accept(_wire(envelope), now_ms=NOW_MS + 2_000)
        assert not again.accepted and again.duplicate


class TestRejects:
    def test_expired_rejected_with_reason(self, inbox, alice_identity):
        envelope = _envelope(alice_identity, ttl_ms=500)
        decision = inbox.accept(envelope, now_ms=NOW_MS + 1_000)
        assert not decision.accepted and "expired" in decision.reason

    def test_future_envelope_rejected(self, inbox, alice_identity):
        from nth_dao.delivery.envelope import MAX_CLOCK_SKEW_MS

        envelope = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"body": "hi"},
            created_at_ms=NOW_MS + MAX_CLOCK_SKEW_MS + 5_000,
            expires_at_ms=NOW_MS + MAX_CLOCK_SKEW_MS + 65_000,
        )
        decision = inbox.accept(envelope, now_ms=NOW_MS + 1_000)
        assert not decision.accepted and "future" in decision.reason

    def test_tampered_payload_rejected_fail_closed(self, inbox, alice_identity):
        """Payload tampering is caught at the payload-hash gate (before the
        signature gate) — either way the envelope must not pass."""

        envelope = _envelope(alice_identity)
        envelope.payload = {"body": "evil"}
        decision = inbox.accept(envelope, now_ms=NOW_MS + 1_000)
        assert not decision.accepted
        assert "payload hash" in decision.reason or "signature" in decision.reason

    def test_signature_tamper_rejected(self, inbox, alice_identity, bob_identity):
        """Signature by a different key than the claimed sender fails."""

        envelope = _envelope(alice_identity)
        # swap in a signature computed by bob over the same body — the body
        # still binds alice as sender, so verification must fail
        from nth_dao.b64u import b64u_encode

        envelope.signature = b64u_encode(bob_identity.sign(
            canonical_json(envelope.signing_body())
        ))
        decision = inbox.accept(envelope, now_ms=NOW_MS + 1_000)
        assert not decision.accepted and "signature" in decision.reason

    def test_non_canonical_json_rejected(self, inbox, alice_identity):
        envelope = _envelope(alice_identity)
        messy = json.dumps(envelope.to_dict(), sort_keys=True, indent=2)
        decision = inbox.accept(messy, now_ms=NOW_MS + 1_000)
        assert not decision.accepted and "canonical" in decision.reason

    def test_garbage_json_rejected(self, inbox):
        decision = inbox.accept("{not json", now_ms=NOW_MS)
        assert not decision.accepted and "JSON" in decision.reason

    def test_non_object_rejected(self, inbox):
        decision = inbox.accept("[1,2,3]", now_ms=NOW_MS)
        assert not decision.accepted and "structure" in decision.reason

    def test_unknown_field_rejected(self, inbox, alice_identity):
        data = _envelope(alice_identity).to_dict()
        data["sneaky"] = True
        decision = inbox.accept(data, now_ms=NOW_MS + 1_000)
        assert not decision.accepted and "structure" in decision.reason

    def test_unsupported_input_type_rejected(self, inbox):
        decision = inbox.accept(42, now_ms=NOW_MS)
        assert not decision.accepted and "unsupported input type" in decision.reason

    def test_decisions_never_carry_envelope_on_reject(self, inbox, alice_identity):
        envelope = _envelope(alice_identity)
        envelope.payload = {"body": "evil"}
        decision = inbox.accept(envelope, now_ms=NOW_MS + 1_000)
        assert decision.envelope is None


class TestAuthorization:
    def test_authorize_deny_rejects_with_reason(self, tmp_path, alice_identity):
        def deny(envelope):
            return False, "not a member"

        inbox = DeliveryInbox(tmp_path / "delivery", clock=lambda: NOW_MS, authorize=deny)
        decision = inbox.accept(_envelope(alice_identity), now_ms=NOW_MS)
        assert not decision.accepted
        assert decision.reason == "not a member"

    def test_authorize_allow_accepts(self, tmp_path, alice_identity):
        inbox = DeliveryInbox(
            tmp_path / "delivery",
            clock=lambda: NOW_MS,
            authorize=lambda envelope: (True, "ok"),
        )
        decision = inbox.accept(_envelope(alice_identity), now_ms=NOW_MS)
        assert decision.accepted

    def test_authorizer_crash_fails_closed(self, tmp_path, alice_identity):
        def explode(envelope):
            raise RuntimeError("membership store offline")

        inbox = DeliveryInbox(
            tmp_path / "delivery", clock=lambda: NOW_MS, authorize=explode
        )
        decision = inbox.accept(_envelope(alice_identity), now_ms=NOW_MS)
        assert not decision.accepted
        assert decision.reason == "authorization callback failed"


class TestReplayCacheBound:
    def test_eviction_oldest_first_and_reload_folds(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(
            directory, clock=lambda: NOW_MS, max_replay_entries=2
        )
        envelopes = [_envelope(alice_identity, payload={"n": i}) for i in range(3)]
        assert inbox.accept(envelopes[0], now_ms=NOW_MS).accepted
        assert inbox.mark_processed(envelopes[0].message_id)
        assert inbox.accept(envelopes[1], now_ms=NOW_MS + 1).accepted
        decision = inbox.accept(envelopes[2], now_ms=NOW_MS + 2)
        assert decision.accepted, decision.reason
        assert inbox.entry_count() == 2
        assert not inbox.seen(envelopes[0].message_id)  # oldest evicted

        reloaded = DeliveryInbox(
            directory, clock=lambda: NOW_MS, max_replay_entries=2
        )
        assert reloaded.entry_count() == 2
        assert not reloaded.seen(envelopes[0].message_id)
        assert reloaded.seen(envelopes[2].message_id)
        # An evicted message can be accepted again after capacity is available.
        assert reloaded.mark_processed(envelopes[1].message_id)
        decision = reloaded.accept(envelopes[0], now_ms=NOW_MS + 10)
        assert decision.accepted, decision.reason

    def test_unprocessed_envelopes_survive_restart(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        envelope = _envelope(alice_identity, payload={"work": "durable"})
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        assert inbox.accept(envelope, now_ms=NOW_MS).accepted

        reloaded = DeliveryInbox(directory, clock=lambda: NOW_MS)
        assert [item.message_id for item in reloaded.pending()] == [
            envelope.message_id
        ]
        assert reloaded.mark_processed(envelope.message_id) is True
        assert reloaded.mark_processed(envelope.message_id) is False
        assert DeliveryInbox(directory, clock=lambda: NOW_MS).pending() == []

    def test_full_inbox_never_evicts_unprocessed_work(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS, max_replay_entries=1)
        first = _envelope(alice_identity, payload={"n": 1})
        second = _envelope(alice_identity, payload={"n": 2})
        assert inbox.accept(first, now_ms=NOW_MS).accepted

        decision = inbox.accept(second, now_ms=NOW_MS + 1)
        assert not decision.accepted
        assert "unprocessed" in decision.reason
        assert [item.message_id for item in inbox.pending()] == [first.message_id]

    def test_rejections_journaled_and_compactable(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        for i in range(5):
            bad = TransportEnvelope.from_dict(_envelope(alice_identity).to_dict())
            bad.payload = {"n": i}
            inbox.accept(bad, now_ms=NOW_MS)
        rejection_path = directory / "inbox.rejections.jsonl"
        assert len(rejection_path.read_text().splitlines()) == 5
        kept = inbox.compact_rejections(max_keep=3)
        assert kept == 3
        assert len(rejection_path.read_text().splitlines()) == 3

    def test_corrupt_cache_fails_closed(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        inbox.accept(_envelope(alice_identity), now_ms=NOW_MS)
        cache = directory / "inbox.cache.jsonl"
        lines = cache.read_bytes().split(b"\n")
        lines[0] = b"{busted"
        cache.write_bytes(b"\n".join(lines))
        with pytest.raises(DeliveryInboxCacheCorrupt):
            DeliveryInbox(directory, clock=lambda: NOW_MS)

    def test_torn_cache_tail_ignored(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        inbox.accept(envelope, now_ms=NOW_MS)
        cache = directory / "inbox.cache.jsonl"
        with open(cache, "ab") as handle:
            handle.write(b'{"event":"acc')
        reloaded = DeliveryInbox(directory, clock=lambda: NOW_MS)
        assert reloaded.seen(envelope.message_id)


class TestCrossProcess:
    def test_two_inboxes_share_cache(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        first = DeliveryInbox(directory, clock=lambda: NOW_MS)
        second = DeliveryInbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        assert first.accept(envelope, now_ms=NOW_MS).accepted
        decision = second.accept(envelope, now_ms=NOW_MS)
        assert not decision.accepted and decision.duplicate

    def test_concurrent_instances_accept_exactly_once(self, tmp_path, alice_identity):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier

        directory = tmp_path / "delivery"
        inboxes = [
            DeliveryInbox(directory, clock=lambda: NOW_MS),
            DeliveryInbox(directory, clock=lambda: NOW_MS),
        ]
        envelope = _envelope(alice_identity)
        barrier = Barrier(2)

        def accept(index):
            barrier.wait(timeout=5)
            return inboxes[index].accept(envelope, now_ms=NOW_MS)

        with ThreadPoolExecutor(max_workers=2) as pool:
            decisions = list(pool.map(accept, range(2)))

        assert sum(decision.accepted for decision in decisions) == 1
        assert sum(decision.duplicate for decision in decisions) == 1
        reloaded = DeliveryInbox(directory, clock=lambda: NOW_MS)
        assert [item.message_id for item in reloaded.pending()] == [
            envelope.message_id
        ]


# ─────────────────── adversarial review round 2 (bugs D + H) ───────────────────


class TestReviewRoundTwo:
    def test_rejection_journal_auto_trims_under_flood(self, tmp_path, alice_identity, monkeypatch):
        """Bug D: a hostile sender flooding malformed envelopes must not grow
        the rejection journal without bound — it auto-trims at the byte cap."""

        import nth_dao.delivery.inbox as inbox_module

        monkeypatch.setattr(inbox_module, "REJECTION_LOG_MAX_BYTES", 2_048)
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        for i in range(300):
            bad = TransportEnvelope.from_dict(_envelope(alice_identity).to_dict())
            bad.payload = {"n": i}
            inbox.accept(bad, now_ms=NOW_MS)
        rejection_path = directory / "inbox.rejections.jsonl"
        assert rejection_path.stat().st_size <= inbox_module.REJECTION_LOG_MAX_BYTES
        lines = rejection_path.read_text().splitlines()
        assert len(lines) > 0
        # intake still works after trimming
        decision = inbox.accept(_envelope(alice_identity, payload={"fresh": 1}), now_ms=NOW_MS + 1)
        assert decision.accepted

    def test_eviction_peek_does_not_mutate_memory_on_write(self, tmp_path, alice_identity, monkeypatch):
        """Bug H regression guard: the cache write path must not mutate
        memory before the durable append — verified here by making the
        second append fail and checking the cache fold still matches."""


        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(
            directory, clock=lambda: NOW_MS, max_replay_entries=1
        )
        first = _envelope(alice_identity, payload={"n": 1})
        second = _envelope(alice_identity, payload={"n": 2})
        assert inbox.accept(first, now_ms=NOW_MS).accepted
        assert inbox.mark_processed(first.message_id)


        def broken_open(*args, **kwargs):
            raise OSError("disk full")

        # The atomic replacement event for `second` cannot be persisted.
        monkeypatch.setattr("builtins.open", broken_open)
        with pytest.raises(OSError):
            inbox.accept(second, now_ms=NOW_MS + 1)
        monkeypatch.undo()

        # memory must still hold ONLY the first entry, exactly as the journal
        # fold of a fresh process would reconstruct it
        assert inbox.entry_count() == 1
        assert inbox.seen(first.message_id)
        assert not inbox.seen(second.message_id)
        reloaded = DeliveryInbox(directory, clock=lambda: NOW_MS, max_replay_entries=1)
        assert reloaded.seen(first.message_id)
        assert not reloaded.seen(second.message_id)


# ─────────────────── adversarial review round 3 (bugs L + P) ───────────────────


class TestReviewRoundThree:
    def test_seen_refolds_other_process_accepts(self, tmp_path, alice_identity):
        """Bug L: seen() must reflect another process's accepts without any
        local accept happening first (stat-based re-fold)."""

        import time as time_mod

        directory = tmp_path / "delivery"
        proc_a = DeliveryInbox(directory, clock=lambda: NOW_MS)
        proc_b = DeliveryInbox(directory, clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        assert proc_b.accept(envelope, now_ms=NOW_MS).accepted
        time_mod.sleep(0.02)  # ensure the journal mtime differs
        assert proc_a.seen(envelope.message_id) is True

    def test_own_accepts_do_not_trigger_refold_storm(self, tmp_path, alice_identity, monkeypatch):
        """Bug P: after our OWN write the stat is updated, so a burst of
        accepts must not re-fold the journal on every call."""


        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        reloads = []
        original_load = inbox._load_cache_locked

        def counting_load():
            reloads.append(1)
            return original_load()

        monkeypatch.setattr(inbox, "_load_cache_locked", counting_load)
        for i in range(20):
            envelope = _envelope(alice_identity, payload={"n": i})
            decision = inbox.accept(envelope, now_ms=NOW_MS + i)
            assert decision.accepted
        assert reloads == []
        assert inbox._cache_stat is not None
        stat = directory / "inbox.cache.jsonl"
        current = stat.stat()
        assert inbox._cache_stat == (current.st_mtime_ns, current.st_size)


# ─────────────────── adversarial review round 4 (bug R) ───────────────────


class TestRejectionTrimLockAndTmp:
    def test_trim_runs_under_lock_with_unique_tmp(self, tmp_path, alice_identity, monkeypatch):
        """Bug R: the flood-trim must hold the cross-process lock and use a
        unique temp name — a deterministic tmp shared with concurrent
        compacts corrupted the journal."""

        import nth_dao.delivery.inbox as inbox_module

        monkeypatch.setattr(inbox_module, "REJECTION_LOG_MAX_BYTES", 2_048)
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        for i in range(300):
            bad = TransportEnvelope.from_dict(_envelope(alice_identity).to_dict())
            bad.payload = {"n": i}
            inbox.accept(bad, now_ms=NOW_MS)

        # no temp leftovers anywhere in the delivery dir
        leftovers = [p for p in directory.iterdir() if p.name.endswith(".tmp")]
        assert leftovers == []
        # nothing was accepted in this flood, so the replay cache is empty —
        # and a fresh inbox folds the (trimmed) journals without error
        reloaded = DeliveryInbox(directory, clock=lambda: NOW_MS)
        assert reloaded.entry_count() == 0
        assert not reloaded.seen("sha256:" + "0" * 64)

    def test_compact_rejections_leaves_no_tmp(self, tmp_path, alice_identity):
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        for i in range(5):
            bad = TransportEnvelope.from_dict(_envelope(alice_identity).to_dict())
            bad.payload = {"n": i}
            inbox.accept(bad, now_ms=NOW_MS)
        inbox.compact_rejections(max_keep=2)
        leftovers = [p for p in directory.iterdir() if p.name.endswith(".tmp")]
        assert leftovers == []


# ─────────────────── adversarial review round 11 (bug BB-p) ───────────────────


class TestCacheJournalAutoCompact:
    def test_oversized_cache_compacts_losslessly_instead_of_bricking(
        self, tmp_path, alice_identity, monkeypatch
    ):
        """Bug BB-p: the cache journal grows monotonically; past the byte cap
        the inbox used to brick itself forever with DeliveryInboxCacheCorrupt.
        Now it folds + rewrites losslessly and keeps working."""

        import nth_dao.delivery.inbox as inbox_module

        monkeypatch.setattr(inbox_module, "MAX_CACHE_JOURNAL_BYTES", 2_048)
        directory = tmp_path / "delivery"
        # eviction (8 live entries) and the journal cap compose: the live
        # state always fits the compacted journal
        inbox = DeliveryInbox(
            directory, clock=lambda: NOW_MS, max_replay_entries=8
        )
        envelopes = []
        for i in range(100):
            envelope = _envelope(alice_identity, payload={"n": i})
            decision = inbox.accept(envelope, now_ms=NOW_MS + i)
            assert decision.accepted, decision.reason
            assert inbox.mark_processed(envelope.message_id)
            envelopes.append(envelope)
        cache = directory / "inbox.cache.jsonl"
        assert cache.stat().st_size <= inbox_module.MAX_CACHE_JOURNAL_BYTES

        # dedup semantics unchanged for every live entry — probe the ORIGINAL
        # envelopes (recreated ones carry fresh nonces and are new messages)
        reloaded = DeliveryInbox(
            directory, clock=lambda: NOW_MS, max_replay_entries=8
        )
        for envelope in envelopes[-8:]:
            decision = reloaded.accept(envelope, now_ms=NOW_MS + 1_000)
            assert decision.duplicate, envelope.message_id
        for envelope in envelopes[:8]:
            assert not reloaded.seen(envelope.message_id)  # evicted long ago
        # and fresh content is still accepted
        fresh = _envelope(alice_identity, payload={"fresh": True})
        decision = reloaded.accept(fresh, now_ms=NOW_MS + 2_000)
        assert decision.accepted

    def test_corrupt_cache_still_fails_closed_after_compact_path(self, tmp_path, alice_identity, monkeypatch):
        """Compaction must not weaken corruption detection: a hostile mid-file
        corruption still fails closed even when the size cap is crossed."""

        import nth_dao.delivery.inbox as inbox_module

        monkeypatch.setattr(inbox_module, "MAX_CACHE_JOURNAL_BYTES", 1_024)
        directory = tmp_path / "delivery"
        inbox = DeliveryInbox(directory, clock=lambda: NOW_MS)
        for i in range(40):
            inbox.accept(_envelope(alice_identity, payload={"n": i}), now_ms=NOW_MS)
        cache = directory / "inbox.cache.jsonl"
        lines = cache.read_bytes().split(b"\n")
        lines[0] = b"{busted"
        cache.write_bytes(b"\n".join(lines))
        with pytest.raises(DeliveryInboxCacheCorrupt):
            DeliveryInbox(directory, clock=lambda: NOW_MS)
