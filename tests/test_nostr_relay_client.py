"""Tests for the Nostr relay client (N2) — sync bridge over a fake relay."""

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
from nth_dao.identity import AgentIdentity  # noqa: E402
from nth_dao.nostr import (  # noqa: E402
    NostrKeys,
    envelope_event,
    envelope_from_event,
)

NOW_MS = 1_750_000_000_000
SEED_SK = "0" * 63 + "1"


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
def nostr_keys():
    return NostrKeys.parse(SEED_SK)


@pytest.fixture()
def fake_relay():
    relay = FakeNostrRelay()
    relay.start()
    yield relay
    relay.stop()


@pytest.fixture()
def relay_client(nostr_keys, fake_relay):
    from nth_dao.nostr import NostrRelayClient

    client = NostrRelayClient(
        nostr_keys, relay_urls=[fake_relay.url], publish_timeout=10.0
    )
    client.start()
    yield client
    client.stop()


def _envelope(alice_identity, payload=None):
    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient="dao:core",
        payload={"body": "public"} if payload is None else payload,
        created_at_ms=int(time.time() * 1000),
        expires_at_ms=int(time.time() * 1000) + 3_600_000,
    )


class TestRelayUrlValidation:
    def test_wss_anywhere(self):
        from nth_dao.nostr import NostrRelayClient

        client = NostrRelayClient(keys=None, relay_urls=["wss://relay.example.com"])
        assert client is not None

    def test_ws_loopback_allowed(self):
        from nth_dao.nostr import NostrRelayClient

        client = NostrRelayClient(keys=None, relay_urls=["ws://127.0.0.1:8080"])
        assert client is not None

    def test_ws_non_loopback_rejected(self):
        from nth_dao.nostr import NostrRelayClient

        with pytest.raises(ValueError, match="wss"):
            NostrRelayClient(keys=None, relay_urls=["ws://relay.example.com"])

    def test_credentials_rejected(self):
        from nth_dao.nostr import NostrRelayClient

        with pytest.raises(ValueError, match="credentials"):
            NostrRelayClient(keys=None, relay_urls=["wss://u:p@relay.example.com"])

    @pytest.mark.parametrize(
        "url",
        [
            " wss://relay.example.com",
            "wss://relay.example.com#fragment",
        ],
    )
    def test_ambiguous_urls_rejected(self, url):
        from nth_dao.nostr import NostrRelayClient

        with pytest.raises(ValueError):
            NostrRelayClient(keys=None, relay_urls=[url])

    def test_empty_and_duplicate_rejected(self):
        from nth_dao.nostr import NostrRelayClient

        with pytest.raises(ValueError, match="relay_urls"):
            NostrRelayClient(keys=None, relay_urls=[])
        with pytest.raises(ValueError, match="duplicates"):
            NostrRelayClient(
                keys=None,
                relay_urls=["wss://a.example.com", "wss://a.example.com"],
            )

    @pytest.mark.parametrize(
        "url",
        ["wss://", "wss://relay.example.com:0", "wss://relay.example.com:99999"],
    )
    def test_invalid_authority_rejected(self, url):
        from nth_dao.nostr import NostrRelayClient

        with pytest.raises(ValueError):
            NostrRelayClient(keys=None, relay_urls=[url])


class TestPublishRoundTrip:
    def test_publish_reaches_relay_and_gets_ok(self, relay_client, fake_relay, alice_identity):
        envelope = _envelope(alice_identity)
        event = envelope_event(envelope, nostr_keys=_keys_for(relay_client), created_at_seconds=int(time.time()))
        result = relay_client.publish(event)
        assert result is True
        assert _wait_until(lambda: len(fake_relay.stored_events()) >= 1)
        stored = fake_relay.stored_events()[0]
        assert stored["content"] == event.content()

    def test_unrunning_client_raises(self, nostr_keys, fake_relay):
        from nth_dao.nostr import NostrRelayClient, NostrRelayError

        client = NostrRelayClient(nostr_keys, relay_urls=[fake_relay.url])
        event = _make_event(nostr_keys)
        with pytest.raises(NostrRelayError, match="not running"):
            client.publish(event)

    def test_relay_rejection_returns_false(self, nostr_keys, fake_relay, alice_identity):
        relay_client = _make_client(nostr_keys, fake_relay)
        fake_relay.set_reject_next(True)
        event = _make_event(nostr_keys)
        result = relay_client.publish(event)
        assert result is False
        fake_relay.set_reject_next(False)


class TestSubscription:
    def test_subscribed_events_delivered(self, nostr_keys, fake_relay, alice_identity):
        from nth_dao.nostr import NostrRelayClient

        client = NostrRelayClient(nostr_keys, relay_urls=[fake_relay.url])
        client.start()
        try:
            client.subscribe_events(kinds=[30078])
            time.sleep(0.3)  # let the REQ land

            sender_keys = NostrKeys.generate()
            envelope = _envelope(alice_identity, payload={"n": 1})
            event = envelope_event(envelope, sender_keys, created_at_seconds=int(time.time()))
            # publish from a second client through the relay
            second = NostrRelayClient(
                sender_keys, relay_urls=[fake_relay.url], name="second"
            )
            second.start()
            try:
                second.publish(event)
            finally:
                second.stop()

            assert _wait_until(lambda: client.queue_depth() >= 1)
            events = client.poll_events()
            assert len(events) == 1
            restored = envelope_from_event(events[0])
            assert restored.message_id == envelope.message_id
        finally:
            client.stop()

    def test_stop_cancels_subscription_pump(self, nostr_keys, fake_relay):
        from nth_dao.nostr import NostrRelayClient

        client = NostrRelayClient(nostr_keys, relay_urls=[fake_relay.url])
        client.start()
        client.subscribe_events(kinds=[30078])
        client.stop()
        assert client._stream_task is None
        assert client._subscription_id is None
        assert client._thread is None

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"kinds": []},
            {"kinds": [True]},
            {"kinds": [1, 1]},
            {"kinds": [70_000]},
            {"kinds": [1], "authors": ["A" * 64]},
            {"kinds": [1], "namespace": "bad\nnamespace"},
            {"kinds": [1], "callback": "not-callable"},
        ],
    )
    def test_subscription_inputs_are_bounded(
        self, nostr_keys, fake_relay, kwargs
    ):
        from nth_dao.nostr import NostrRelayClient

        client = NostrRelayClient(nostr_keys, relay_urls=[fake_relay.url])
        client.start()
        try:
            with pytest.raises((TypeError, ValueError)):
                client.subscribe_events(**kwargs)
        finally:
            client.stop()

    @pytest.mark.parametrize("value", [True, float("nan"), float("inf"), "1"])
    def test_publish_timeout_shape_rejected(self, nostr_keys, fake_relay, value):
        from nth_dao.nostr import NostrRelayClient

        with pytest.raises((TypeError, ValueError)):
            NostrRelayClient(
                nostr_keys,
                relay_urls=[fake_relay.url],
                publish_timeout=value,
            )


class TestHostileRelay:
    def test_rejecting_relay_returns_false(self, nostr_keys, fake_relay):
        client = _make_client(nostr_keys, fake_relay)
        fake_relay.set_reject_next(True)
        event = _make_event(nostr_keys)
        assert client.publish(event) is False
        fake_relay.set_reject_next(False)


def _make_client(keys, fake_relay):
    from nth_dao.nostr import NostrRelayClient

    client = NostrRelayClient(keys, relay_urls=[fake_relay.url], publish_timeout=10.0)
    client.start()
    return client


def _keys_for(client):
    return client._keys


def _make_event(nostr_keys):
    from nth_dao.delivery.envelope import sign_envelope
    from nth_dao.identity import AgentIdentity
    from nth_dao.nostr import envelope_event

    ident = AgentIdentity.generate(label="probe")
    envelope = sign_envelope(
        ident, kind="channel.message", recipient="dao:core",
        payload={"probe": True},
        created_at_ms=int(time.time() * 1000),
        expires_at_ms=int(time.time() * 1000) + 600_000,
    )
    return envelope_event(envelope, nostr_keys, created_at_seconds=int(time.time()))
