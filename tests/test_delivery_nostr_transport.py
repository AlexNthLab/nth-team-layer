"""Tests for the Nostr delivery transport (N3) — transport adapter over a
fake relay, wired into the delivery router."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("nostr_sdk")
pytest.importorskip("nacl")
pytest.importorskip("websockets")

sys.path.insert(0, str(Path(__file__).parent))
from fake_nostr_relay import FakeNostrRelay  # noqa: E402

from nth_dao.delivery.envelope import sign_envelope  # noqa: E402
from nth_dao.delivery.transports.base import (  # noqa: E402
    PRIVACY_PUBLIC_RELAY,
)
from nth_dao.delivery.transports.nostr import NostrTransport  # noqa: E402
from nth_dao.identity import AgentIdentity  # noqa: E402
from nth_dao.nostr import NostrKeyBinding, NostrKeys, sign_key_binding  # noqa: E402


def _wait_until(predicate, timeout=10.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.fixture()
def alice_identity():
    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def fake_relay():
    relay = FakeNostrRelay()
    relay.start()
    yield relay
    relay.stop()


def _envelope(alice_identity, payload=None):
    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient="dao:core",
        payload={"body": "public"} if payload is None else payload,
        created_at_ms=int(time.time() * 1000),
        expires_at_ms=int(time.time() * 1000) + 3_600_000,
    )


def _transport(identity, fake_relay, *, keys=None, trusted_bindings=None):
    keys = keys or NostrKeys.generate()
    binding = sign_key_binding(
        identity, nostr_keys=keys, created_at_ms=int(time.time() * 1000)
    )
    return NostrTransport(
        keys,
        relay_urls=[fake_relay.url],
        binding=binding,
        trusted_bindings=trusted_bindings,
    ), binding


class TestNostrTransport:
    def test_capabilities_declare_public_broadcast(self, alice_identity, fake_relay):
        transport, _ = _transport(alice_identity, fake_relay)
        caps = transport.capabilities
        assert caps.broadcast is True
        assert caps.privacy_level == PRIVACY_PUBLIC_RELAY
        assert caps.external_infrastructure is True

    def test_send_and_poll_roundtrip(self, alice_identity, fake_relay):
        sender, sender_binding = _transport(alice_identity, fake_relay)
        receiver_identity = AgentIdentity.generate(label="receiver")
        receiver, _ = _transport(
            receiver_identity,
            fake_relay,
            trusted_bindings=[sender_binding],
        )
        sender.start()
        receiver.start()
        try:
            time.sleep(0.3)  # let subscriptions land
            envelope = _envelope(alice_identity, payload={"n": 1})
            result = sender.send(envelope)
            assert result.accepted, result.error_code
            assert _wait_until(lambda: receiver._relay_client.queue_depth() >= 1)
            polled = receiver.poll()
            assert polled[0].message_id == envelope.message_id
        finally:
            sender.stop()
            receiver.stop()

    def test_private_did_recipient_rejected(self, alice_identity, fake_relay):
        from nth_dao.identity import AgentIdentity

        transport, _ = _transport(alice_identity, fake_relay)
        transport.start()
        try:
            bob = AgentIdentity.generate(label="bob")
            private_dm = sign_envelope(
                alice_identity,
                kind="dm.message",
                recipient=bob.as_did(),
                payload={"secret": "private"},
                created_at_ms=int(time.time() * 1000),
                expires_at_ms=int(time.time() * 1000) + 60_000,
            )
            result = transport.send(private_dm)
            assert not result.accepted
            assert "broadcast traffic only" in result.error_code
        finally:
            transport.stop()


# ─────────────────── adversarial review round 16 (bug DD-a) ───────────────────


class TestBindingThroughTransport:
    def test_transport_passes_binding_to_envelope_event(self, alice_identity, fake_relay):
        """Bug DD-a: the transport's send() must pass the binding through so
        the N1 publish-side enforcement is not bypassed at the transport tier."""

        from nth_dao.nostr import NostrKeys, sign_key_binding

        keys = NostrKeys.generate()
        binding = sign_key_binding(
            alice_identity, nostr_keys=keys, created_at_ms=int(time.time() * 1000)
        )
        transport = NostrTransport(
            keys, relay_urls=[fake_relay.url], binding=binding
        )
        transport.start()
        try:
            envelope = _envelope(alice_identity)
            result = transport.send(envelope)
            assert result.accepted, result.error_code
        finally:
            transport.stop()

    def test_transport_without_binding_is_rejected(self, alice_identity, fake_relay):
        keys = NostrKeys.generate()
        with pytest.raises(TypeError, match="binding"):
            NostrTransport(keys, relay_urls=[fake_relay.url])

    def test_forged_binding_is_rejected(self, alice_identity, fake_relay):
        keys = NostrKeys.generate()
        forged = NostrKeyBinding(
            nth_did=alice_identity.as_did(),
            nostr_pubkey=keys.public_key_hex,
            created_at_ms=int(time.time() * 1000),
            signature="0" * 128,
        )
        with pytest.raises(ValueError, match="signature verification failed"):
            NostrTransport(keys, relay_urls=[fake_relay.url], binding=forged)

    def test_same_time_rotation_conflict_is_rejected(
        self, alice_identity, fake_relay
    ):
        created_at_ms = int(time.time() * 1000)
        old_keys = NostrKeys.generate()
        new_keys = NostrKeys.generate()
        old_binding = sign_key_binding(
            alice_identity,
            nostr_keys=old_keys,
            created_at_ms=created_at_ms,
        )
        new_binding = sign_key_binding(
            alice_identity,
            nostr_keys=new_keys,
            created_at_ms=created_at_ms,
        )
        with pytest.raises(ValueError, match="conflicting Nostr bindings"):
            NostrTransport(
                old_keys,
                relay_urls=[fake_relay.url],
                binding=old_binding,
                trusted_bindings=[new_binding],
            )

    def test_unknown_nostr_author_is_dropped(
        self, alice_identity, fake_relay
    ):
        from nth_dao.nostr import envelope_event

        receiver_identity = AgentIdentity.generate(label="receiver")
        receiver, _ = _transport(receiver_identity, fake_relay)
        unknown_keys = NostrKeys.generate()
        event = envelope_event(
            _envelope(alice_identity),
            unknown_keys,
            created_at_seconds=int(time.time()),
        )
        with receiver._relay_client._queue_lock:
            receiver._relay_client._queue.append(event)
        assert receiver.poll() == []

    def test_trusted_relay_key_cannot_speak_for_another_did(
        self, alice_identity, fake_relay
    ):
        from nth_dao.nostr import envelope_event

        mallory_identity = AgentIdentity.generate(label="mallory")
        mallory_keys = NostrKeys.generate()
        mallory_binding = sign_key_binding(
            mallory_identity,
            nostr_keys=mallory_keys,
            created_at_ms=int(time.time() * 1000),
        )
        receiver_identity = AgentIdentity.generate(label="receiver")
        receiver, _ = _transport(
            receiver_identity,
            fake_relay,
            trusted_bindings=[mallory_binding],
        )
        event = envelope_event(
            _envelope(alice_identity),
            mallory_keys,
            created_at_seconds=int(time.time()),
        )
        with receiver._relay_client._queue_lock:
            receiver._relay_client._queue.append(event)
        assert receiver.poll() == []

    def test_only_latest_binding_for_a_did_is_accepted(
        self, alice_identity, fake_relay
    ):
        from nth_dao.nostr import envelope_event

        now_ms = int(time.time() * 1000)
        old_keys = NostrKeys.generate()
        new_keys = NostrKeys.generate()
        old_binding = sign_key_binding(
            alice_identity,
            nostr_keys=old_keys,
            created_at_ms=now_ms - 1_000,
        )
        new_binding = sign_key_binding(
            alice_identity,
            nostr_keys=new_keys,
            created_at_ms=now_ms,
        )
        receiver_identity = AgentIdentity.generate(label="receiver")
        receiver, _ = _transport(
            receiver_identity,
            fake_relay,
            trusted_bindings=[old_binding, new_binding],
        )
        envelope = _envelope(alice_identity)
        old_event = envelope_event(
            envelope, old_keys, created_at_seconds=int(time.time())
        )
        new_event = envelope_event(
            envelope, new_keys, created_at_seconds=int(time.time())
        )
        with receiver._relay_client._queue_lock:
            receiver._relay_client._queue.extend([old_event, new_event])
        accepted = receiver.poll(max_items=2)
        assert [item.message_id for item in accepted] == [envelope.message_id]


# ─────────────────── adversarial review round 16 (bug DD-d) ───────────────────


class TestSubscriptionFailureDegradation:
    def test_subscription_failure_degrades_to_publish_only(self, alice_identity, fake_relay, monkeypatch):
        """Bug DD-d: subscription setup failure must not prevent the
        transport from publishing — it degrades to publish-only mode.

        The stop() → start() restart races the relay connection teardown;
        a short settle wait makes the restart deterministic."""

        from nth_dao.nostr import NostrKeys

        keys = NostrKeys.generate()
        binding = sign_key_binding(
            alice_identity,
            nostr_keys=keys,
            created_at_ms=int(time.time() * 1000),
        )
        transport = NostrTransport(
            keys, relay_urls=[fake_relay.url], binding=binding
        )
        transport.start()

        def broken_subscribe(*args, **kwargs):
            raise RuntimeError("stream API broken")

        monkeypatch.setattr(
            transport._relay_client, "subscribe_events", broken_subscribe
        )

        # re-start with the broken subscription — should not raise
        transport.stop()
        time.sleep(0.2)  # let the relay settle the disconnect
        transport.start()
        monkeypatch.undo()

        # publish still works (retry loop absorbs reconnect jitter)
        envelope = _envelope(alice_identity, payload={"n": 1})
        result = None
        for _ in range(5):
            result = transport.send(envelope)
            if result.accepted:
                break
            time.sleep(0.3)
        assert result.accepted, result.error_code
        # poll returns empty (no subscription)
        assert transport.poll() == []
        transport.stop()
