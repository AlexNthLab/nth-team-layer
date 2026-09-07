"""Tests for the Nostr adapter core (N1) — keys, bindings, envelope events.

All crypto runs through the borrowed ``nostr-sdk``; these tests pin the NTH
mapping (binding semantics, envelope wrap/unwrap, tamper rejection) with
deterministic keys. No relay network needed for this segment.
"""

from __future__ import annotations

import json
import time

import pytest

pytest.importorskip("nostr_sdk")
pytest.importorskip("nacl")

NOW_MS = 1_750_000_000_000
SEED_SK = "0" * 63 + "1"  # deterministic test secret key


@pytest.fixture()
def alice_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def nostr_keys():
    from nth_dao.nostr import NostrKeys

    return NostrKeys.parse(SEED_SK)


def _envelope(alice_identity, payload=None):
    from nth_dao.delivery.envelope import sign_envelope

    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient="dao:core",
        payload={"body": "hi"} if payload is None else payload,
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 3_600_000,
    )


class TestNostrKeys:
    def test_parse_is_deterministic(self, nostr_keys):
        assert nostr_keys.public_key_hex == nostr_keys.public_key_hex
        from nth_dao.nostr import NostrKeys

        assert NostrKeys.parse(SEED_SK).public_key_hex == nostr_keys.public_key_hex
        assert len(nostr_keys.public_key_hex) == 64

    def test_invalid_secret_rejected(self):
        from nth_dao.nostr import NostrKeys

        with pytest.raises(ValueError, match="invalid nostr secret key"):
            NostrKeys.parse("zzzz")
        with pytest.raises(ValueError, match="hex text"):
            NostrKeys.parse(123)


class TestKeyBinding:
    def test_sign_and_verify(self, alice_identity, nostr_keys):
        from nth_dao.nostr import sign_key_binding, verify_key_binding

        binding = sign_key_binding(
            alice_identity, nostr_keys=nostr_keys, created_at_ms=NOW_MS
        )
        ok, reason = verify_key_binding(
            binding, identity=alice_identity, now_ms=NOW_MS + 1_000
        )
        assert ok, reason

    def test_wrong_identity_fails(self, alice_identity, nostr_keys):
        from nth_dao.identity import AgentIdentity
        from nth_dao.nostr import sign_key_binding, verify_key_binding

        binding = sign_key_binding(
            alice_identity, nostr_keys=nostr_keys, created_at_ms=NOW_MS
        )
        mallory = AgentIdentity.generate(label="mallory")
        ok, reason = verify_key_binding(binding, identity=mallory, now_ms=NOW_MS)
        assert not ok and "does not match" in reason

    def test_tampered_signature_fails(self, alice_identity, nostr_keys):
        from nth_dao.nostr import sign_key_binding, verify_key_binding

        binding = sign_key_binding(
            alice_identity, nostr_keys=nostr_keys, created_at_ms=NOW_MS
        )
        from dataclasses import replace

        tampered = replace(binding, nostr_pubkey="f" * 64)
        ok, reason = verify_key_binding(
            tampered, identity=alice_identity, now_ms=NOW_MS
        )
        assert not ok and "signature" in reason

    def test_future_binding_rejected(self, alice_identity, nostr_keys):
        from nth_dao.nostr import sign_key_binding, verify_key_binding

        binding = sign_key_binding(
            alice_identity, nostr_keys=nostr_keys, created_at_ms=NOW_MS + 500_000
        )
        ok, reason = verify_key_binding(
            binding, identity=alice_identity, now_ms=NOW_MS
        )
        assert not ok and "past" in reason

    def test_stale_binding_rejected(self, alice_identity, nostr_keys):
        from nth_dao.nostr import (
            BINDING_MAX_AGE_MS,
            sign_key_binding,
            verify_key_binding,
        )

        binding = sign_key_binding(
            alice_identity,
            nostr_keys=nostr_keys,
            created_at_ms=NOW_MS - BINDING_MAX_AGE_MS - 1,
        )
        ok, reason = verify_key_binding(
            binding,
            identity=alice_identity,
            now_ms=NOW_MS,
        )
        assert not ok and "re-issued" in reason


class TestEnvelopeEvent:
    def test_roundtrip_verify(self, alice_identity, nostr_keys):
        from nth_dao.nostr import NOSTR_EVENT_KIND, envelope_event, envelope_from_event

        envelope = _envelope(alice_identity, payload={"title": "public mission"})
        event = envelope_event(envelope, nostr_keys, created_at_seconds=NOW_MS // 1000)
        assert event.kind().as_u16() == NOSTR_EVENT_KIND
        # the d tag pins the message id for parameterized addressing
        assert envelope.message_id in event.as_json()
        restored = envelope_from_event(event)
        assert restored.message_id == envelope.message_id
        assert restored.payload == {"title": "public mission"}

    def test_tampered_content_rejected(self, alice_identity, nostr_keys):
        import json as jsonlib

        from nth_dao.nostr import envelope_event, envelope_from_event

        envelope = _envelope(alice_identity)
        event = envelope_event(envelope, nostr_keys, created_at_seconds=NOW_MS // 1000)
        document = jsonlib.loads(event.as_json())
        document["content"] = jsonlib.dumps(
            {**jsonlib.loads(document["content"]), "body": "evil"},
            separators=(",", ":"), sort_keys=True,
        )
        tampered = type(event).from_json(jsonlib.dumps(document))
        with pytest.raises(Exception):
            envelope_from_event(tampered)

    def test_unsigned_envelope_rejected_before_event(self, alice_identity, nostr_keys):
        from nth_dao.delivery.envelope import TransportEnvelopeRejected
        from nth_dao.nostr import envelope_event

        envelope = _envelope(alice_identity)
        envelope.signature = ""
        with pytest.raises(TransportEnvelopeRejected, match="signature"):
            envelope_event(envelope, nostr_keys, created_at_seconds=NOW_MS // 1000)

    def test_wrong_kind_rejected(self, alice_identity, nostr_keys):
        from nostr_sdk import EventBuilder, Kind

        from nth_dao.nostr import envelope_from_event

        envelope = _envelope(alice_identity)
        event = EventBuilder(Kind(1), jsonlib_content(envelope)).finalize(nostr_keys.raw)
        with pytest.raises(Exception, match="wrong nostr event kind"):
            envelope_from_event(event)


def jsonlib_content(envelope):
    from nth_dao.canonical_json import canonical_json

    return canonical_json(envelope.to_dict()).decode("utf-8")


# ─────────────────── adversarial review round 12 (BB-q / BB-r) ───────────────────


class TestDTagAddressing:
    def test_hostile_d_tag_slot_collision_rejected(self, alice_identity, nostr_keys):
        """Bug BB-q: a valid envelope wrapped in an event whose d tag names a
        DIFFERENT message id must be rejected — the d tag is the addressing
        key of the parameterized-replaceable event."""

        from nostr_sdk import EventBuilder, Kind, Tag

        from nth_dao.nostr import NOSTR_NAMESPACE, envelope_event, envelope_from_event

        envelope = _envelope(alice_identity, payload={"n": 1})
        event = envelope_event(envelope, nostr_keys, created_at_seconds=NOW_MS // 1000)
        hostile = EventBuilder(
            Kind(30078),
            json.dumps(envelope.to_dict(), separators=(",", ":"), sort_keys=True),
        ).tags([
            Tag.parse(["d", "someone-elses-message-id"]),
            Tag.parse(["t", NOSTR_NAMESPACE]),
        ])
        hostile_event = hostile.finalize(nostr_keys.raw)
        with pytest.raises(Exception, match="d tag does not address"):
            envelope_from_event(hostile_event)
        # the honest event still verifies end to end
        assert envelope_from_event(event).message_id == envelope.message_id

    def test_created_at_seconds_strictly_validated(self, alice_identity, nostr_keys):
        """Bug BB-r: floats, negatives, and far-future timestamps must be
        refused before the event touches the wire."""

        from nth_dao.delivery.envelope import TransportEnvelopeRejected
        from nth_dao.nostr import envelope_event

        envelope = _envelope(alice_identity)
        real_now = int(time.time())
        for hostile in (1750000000.5, -1, 0, real_now + 7200, True):
            with pytest.raises(TransportEnvelopeRejected, match="created_at_seconds"):
                envelope_event(envelope, nostr_keys, created_at_seconds=hostile)
        # one hour of future allowance is accepted (relative to the real clock)
        event = envelope_event(
            envelope, nostr_keys, created_at_seconds=real_now + 1800
        )
        assert event.kind().as_u16() == 30078


# ─────────────────── adversarial review round 13 (bug BB-t) ───────────────────


class TestDeterministicTimestamps:
    def test_created_at_seconds_is_actually_applied(self, alice_identity, nostr_keys):
        """Bug BB-t: the validated created_at_seconds used to be silently
        dropped (wall clock applied instead) — deterministic replay was
        impossible. Two events with different timestamps must differ; the
        same timestamp must reproduce the same event id."""

        from nth_dao.nostr import envelope_event

        envelope = _envelope(alice_identity, payload={"n": 1})
        ev_early = envelope_event(
            envelope, nostr_keys, created_at_seconds=1_000_000_000
        )
        ev_late = envelope_event(
            envelope, nostr_keys, created_at_seconds=1_700_000_000
        )
        assert ev_early.created_at().as_secs() == 1_000_000_000
        assert ev_late.created_at().as_secs() == 1_700_000_000
        assert ev_early.id().to_hex() != ev_late.id().to_hex()

    def test_same_inputs_reproduce_identical_event_id(self, alice_identity, nostr_keys):
        from nth_dao.nostr import envelope_event

        envelope = _envelope(alice_identity, payload={"n": 1})
        first = envelope_event(envelope, nostr_keys, created_at_seconds=1_700_000_000)
        second = envelope_event(envelope, nostr_keys, created_at_seconds=1_700_000_000)
        # id determinism: content + created_at + pubkey fully determine the id
        assert first.id().to_hex() == second.id().to_hex()
        # signatures differ across runs (BIP340 aux randomness is allowed by
        # the spec and nostr-sdk uses it) — both must verify though
        assert second.verify_signature()


# ─────────────────── adversarial review round 14 ───────────────────


class TestHardening:
    def test_deeply_nested_content_never_escapes(self, alice_identity, nostr_keys):
        """Round-14 hardening: even at extreme depth (100k) a hostile content
        blob is rejected through the contract type, never a raw RecursionError."""

        from nostr_sdk import EventBuilder, Kind, Tag

        from nth_dao.delivery.envelope import TransportEnvelopeRejected
        from nth_dao.nostr import envelope_from_event

        deep = "{" + '"a":' * 100_000 + "1" + "}" * 100_000
        hostile = (
            EventBuilder(Kind(30078), deep)
            .tags([Tag.parse(["d", "x"])])
            .finalize(nostr_keys.raw)
        )
        with pytest.raises(TransportEnvelopeRejected):
            envelope_from_event(hostile)

    def test_event_without_d_tag_rejected(self, alice_identity, nostr_keys):
        """Addressing requires exactly the d tag naming the message id — an
        event with no d tag cannot be routed to an envelope."""

        import json as jsonlib

        from nostr_sdk import EventBuilder, Kind, Tag

        from nth_dao.nostr import NOSTR_NAMESPACE, envelope_from_event

        envelope = _envelope(alice_identity)
        event = EventBuilder(
            Kind(30078),
            jsonlib.dumps(envelope.to_dict(), separators=(",", ":"), sort_keys=True),
        ).tags([Tag.parse(["t", NOSTR_NAMESPACE])]).finalize(nostr_keys.raw)
        with pytest.raises(Exception, match="d tag does not address"):
            envelope_from_event(event)


# ─────────────────── adversarial review round 17 (BB-w2) ───────────────────


class TestExpirationTag:
    def test_nip40_expiration_tag_present(self, alice_identity, nostr_keys):
        """Bug BB-w2: the event must carry a NIP-40 expiration tag derived
        from the envelope's TTL — without it, expired envelopes remain
        world-readable on relays indefinitely."""

        from nth_dao.nostr import envelope_event

        envelope = _envelope(alice_identity, payload={"n": 1})
        event = envelope_event(envelope, nostr_keys, created_at_seconds=int(time.time()))
        tags = [tag.to_vec() for tag in event.tags()]
        exp_tags = [tag for tag in tags if tag[0] == "expiration"]
        assert len(exp_tags) == 1, f"expected exactly one expiration tag, got {tags}"
        expected_seconds = str(envelope.expires_at_ms // 1000)
        assert exp_tags[0][1] == expected_seconds

    def test_d_tag_still_present_alongside_expiration(self, alice_identity, nostr_keys):
        from nth_dao.nostr import envelope_event

        envelope = _envelope(alice_identity, payload={"n": 1})
        event = envelope_event(envelope, nostr_keys, created_at_seconds=int(time.time()))
        tags = [tag.to_vec() for tag in event.tags()]
        d_tags = [tag for tag in tags if tag[0] == "d"]
        assert len(d_tags) == 1
        assert d_tags[0][1] == envelope.message_id
