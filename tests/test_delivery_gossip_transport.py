"""Tests for the WebSocket gossip delivery transport.

Two real GossipNodes over real localhost WebSockets (borrowed layer, real
wire), driven through the synchronous Transport contract. Skips when the
``websockets`` extra is absent — same policy as ``nth_dao.gossip``.
"""

from __future__ import annotations

import json
import time

import pytest

from nth_dao.delivery.envelope import sign_envelope
from nth_dao.delivery.transports.base import PRIVACY_PEER

pytest.importorskip("nacl")
pytest.importorskip("websockets")

NOW_MS = 1_750_000_000_000
STARTUP_TIMEOUT = 20.0


@pytest.fixture()
def alice_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def bob_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="bob")


def _envelope(alice_identity, payload=None, recipient="dao:core"):
    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient=recipient,
        payload={"body": "hi"} if payload is None else payload,
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 120_000,
    )


def _wait_until(predicate, timeout=10.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.fixture()
def alice_transport(alice_identity, bob_identity):
    from nth_dao.delivery.transports.websocket_gossip import WebSocketGossipTransport

    transport = WebSocketGossipTransport(
        alice_identity,
        port=0,
        trusted_pubkeys={str(bob_identity.agent_id): bob_identity.pubkey_hex},
    )
    transport.start()
    yield transport
    transport.stop()


@pytest.fixture()
def bob_transport(bob_transport_factory):
    transport = bob_transport_factory("127.0.0.1", None)
    transport.start()
    yield transport
    transport.stop()


@pytest.fixture()
def bob_transport_factory(bob_identity, alice_identity):
    created = []

    def _make(host, port):
        from nth_dao.delivery.transports.websocket_gossip import WebSocketGossipTransport

        transport = WebSocketGossipTransport(
            bob_identity,
            host=host,
            port=port if port is not None else 0,
            trusted_pubkeys={str(alice_identity.agent_id): alice_identity.pubkey_hex},
        )
        created.append(transport)
        return transport

    yield _make
    for transport in created:
        transport.stop()


class TestGossipTransportLifecycle:
    def test_start_returns_url_and_stops_cleanly(self, alice_transport):
        assert alice_transport.url.startswith("ws://")
        assert alice_transport.capabilities.name == "gossip-ws"
        assert alice_transport.health().reachable is True
        alice_transport.stop()
        assert alice_transport.health().reachable is False
        # double stop must be a safe no-op
        alice_transport.stop()

    def test_send_without_peers_rejected(self, alice_identity, alice_transport):
        result = alice_transport.send(_envelope(alice_identity))
        assert not result.accepted
        assert result.error_code == "no-connected-peers"

    def test_send_after_stop_rejected(self, alice_identity):
        from nth_dao.delivery.transports.websocket_gossip import WebSocketGossipTransport

        transport = WebSocketGossipTransport(alice_identity, port=0)
        transport.start()
        transport.stop()
        result = transport.send(_envelope(alice_identity))
        assert not result.accepted
        assert result.error_code == "transport-stopped"

    def test_capabilities_declare_realtime_peer_broadcast(self, alice_transport):
        caps = alice_transport.capabilities
        assert caps.realtime is True
        assert caps.broadcast is True
        assert caps.unicast is True
        assert caps.privacy_level == PRIVACY_PEER
        assert caps.external_infrastructure is False

    def test_tofu_is_explicit_not_default(self, alice_identity, bob_identity):
        from nth_dao.delivery.transports.websocket_gossip import WebSocketGossipTransport

        alice = WebSocketGossipTransport(alice_identity, port=0)
        bob = WebSocketGossipTransport(bob_identity, port=0)
        try:
            alice.start()
            bob.start()
            assert asyncio_run(bob, alice.url) is False
            assert alice.peer_count() == 0
            assert bob.peer_count() == 0
        finally:
            bob.stop()
            alice.stop()


class TestGossipWire:
    def test_two_nodes_exchange_envelopes(self, alice_identity, alice_transport, bob_transport_factory):
        bob = bob_transport_factory("127.0.0.1", None)
        bob.start()
        # bob connects to alice's gossip endpoint (on bob's own loop)
        import asyncio

        bob_future = asyncio.run_coroutine_threadsafe(
            bob._node.connect(alice_transport.url), bob._loop
        )
        assert bob_future.result(timeout=10.0) is True
        assert _wait_until(lambda: alice_transport.peer_count() >= 1)
        assert _wait_until(lambda: bob.peer_count() >= 1)

        envelope = _envelope(alice_identity, payload={"n": 1})
        result = alice_transport.send(envelope)
        assert result.accepted, result.error_code

        # non-consuming wait: poll() drains, so watch the queue depth
        assert _wait_until(lambda: len(bob._inbox) >= 1)
        received = bob.poll()
        assert len(received) == 1
        assert received[0].message_id == envelope.message_id

    def test_direct_did_never_falls_back_to_broadcast(
        self,
        alice_identity,
        bob_identity,
        alice_transport,
        bob_transport_factory,
    ):
        from nth_dao.identity import AgentIdentity

        bob = bob_transport_factory("127.0.0.1", None)
        bob.start()
        assert asyncio_run(bob, alice_transport.url) is True
        assert _wait_until(lambda: alice_transport.peer_count() >= 1)

        relay_calls = []
        original_relay = bob._node._relay

        async def observe_relay(message, exclude=""):
            relay_calls.append((message, exclude))
            return await original_relay(message, exclude=exclude)

        bob._node._relay = observe_relay

        direct = _envelope(
            alice_identity,
            payload={"body": "bob only"},
            recipient=bob_identity.as_did(),
        )
        assert alice_transport.send(direct).accepted
        assert _wait_until(lambda: len(bob._inbox) == 1)
        assert bob.poll()[0].message_id == direct.message_id
        assert relay_calls == []

        unknown = AgentIdentity.generate(label="unknown")
        not_connected = _envelope(
            alice_identity,
            payload={"body": "must not leak"},
            recipient=unknown.as_did(),
        )
        result = alice_transport.send(not_connected)
        assert not result.accepted
        assert result.error_code == "recipient-not-directly-connected"
        time.sleep(0.1)
        assert bob.poll() == []

    def test_direct_outer_target_cannot_override_inner_recipient(
        self, alice_identity, bob_identity, alice_transport
    ):
        from nth_dao.identity import AgentIdentity

        carol = AgentIdentity.generate(label="carol")
        envelope = _envelope(
            alice_identity,
            payload={"body": "for carol"},
            recipient=carol.as_did(),
        )
        alice_transport._on_gossip_message(
            {
                "content": json.dumps(
                    envelope.to_dict(), separators=(",", ":"), sort_keys=True
                )
            },
            relay_peer_id=str(bob_identity.agent_id),
        )
        assert alice_transport.poll() == []

    def test_non_envelope_gossip_ignored(self, alice_identity, alice_transport, bob_transport_factory):
        bob = bob_transport_factory("127.0.0.1", None)
        bob.start()
        bob_future = asyncio_run(bob, alice_transport.url)
        assert bob_future is True
        assert _wait_until(lambda: bob.peer_count() >= 1)

        # alice gossips plain chat content (not an envelope) through the node
        asyncio_run_coro(alice_transport, alice_transport._node.broadcast(
            "just chatting", scope="dao", content_type="text"
        ))
        time.sleep(0.5)
        assert bob.poll() == []  # non-envelope content never surfaces

    def test_inbound_queue_bounded_under_flood(self, alice_identity, bob_transport_factory, monkeypatch):
        from nth_dao.delivery.transports import websocket_gossip as wg

        bob = bob_transport_factory("127.0.0.1", None)
        # flood the callback directly: no peer needed
        for i in range(wg._INBOUND_QUEUE_SIZE + 50):
            envelope = _envelope(alice_identity, payload={"n": i})
            bob._on_gossip_message(
                {"content": json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":"))},
                relay_peer_id="",
            )
        # bounded: never exceeds the cap, oldest dropped
        assert len(bob._inbox) == wg._INBOUND_QUEUE_SIZE
        first = bob.poll(max_items=1)[0]
        assert first.payload["n"] == 50  # oldest 50 evicted

    def test_malformed_content_dropped_silently(self, bob_transport_factory):
        bob = bob_transport_factory("127.0.0.1", None)
        bob._on_gossip_message({"content": "{not json"}, relay_peer_id="")
        bob._on_gossip_message({"content": "[1,2,3]"}, relay_peer_id="")
        bob._on_gossip_message({}, relay_peer_id="")
        assert bob.poll() == []


def asyncio_run_coro(transport, coro):
    import asyncio

    fut = asyncio.run_coroutine_threadsafe(coro, transport._loop)
    return fut.result(timeout=10.0)


def asyncio_run(bob, url):
    import asyncio

    fut = asyncio.run_coroutine_threadsafe(bob._node.connect(url), bob._loop)
    return fut.result(timeout=10.0)


# ─────────────────── adversarial review round 5 (bug U) ───────────────────


class TestRestart:
    def test_restart_after_stop_gets_fresh_url_and_state(self, alice_identity):
        """Bug U: stop() then start() must clear the stale startup event —
        the second start() must not return before the new node has bound its
        port, and the url must be the NEW node's."""

        from nth_dao.delivery.transports.websocket_gossip import WebSocketGossipTransport

        transport = WebSocketGossipTransport(alice_identity, port=0)
        transport.start()
        url1 = transport.url
        assert url1.startswith("ws://")
        transport.stop()
        assert transport.health().reachable is False

        transport.start()
        url2 = transport.url
        assert url2.startswith("ws://")
        assert url2 != url1  # fresh bind on a fresh ephemeral port
        assert transport.health().reachable is True
        # send must report honest state (no peers), not transport-stopped
        result = transport.send(_envelope(alice_identity))
        assert not result.accepted
        assert result.error_code == "no-connected-peers"
        transport.stop()


# ─────────────────── adversarial review round 6 (bug W) ───────────────────


class TestMidflightPeerDrop:
    def test_send_fails_honestly_when_all_peers_drop_midflight(self, alice_identity, alice_transport):
        """Bug W: a peer present at the pre-check but gone by broadcast time
        must NOT produce a false accept — the outbox has to retry."""

        envelope = _envelope(alice_identity, payload={"n": 1})

        real_broadcast = alice_transport._node.broadcast

        async def vanishing_broadcast(
            content, scope="dao", content_type="json", **kwargs
        ):
            # every peer disconnects inside the send window
            alice_transport._node.peers.clear()
            return await real_broadcast(
                content, scope=scope, content_type=content_type, **kwargs
            )

        # instance attribute shadows the bound method (called without self)
        alice_transport._node.broadcast = vanishing_broadcast

        # pretend one peer is connected so the pre-check passes
        class _FakeSocket:
            async def close(self):
                pass

        alice_transport._node.peers["p1"] = _FakeSocket()
        result = alice_transport.send(envelope)
        assert not result.accepted
        assert result.error_code == "no-connected-peers"


# ─────────────────── adversarial review round 6 (bug X) ───────────────────


class TestProxyIsolation:
    def test_start_does_not_mutate_process_proxy_environment(
        self, alice_identity, monkeypatch
    ):
        """Starting one transport must not alter networking for the process."""

        import os

        from nth_dao.delivery.transports.websocket_gossip import WebSocketGossipTransport

        monkeypatch.setenv("no_proxy", "foo.example.com")
        monkeypatch.setenv("NO_PROXY", "foo.example.com")
        transport = WebSocketGossipTransport(alice_identity, port=0)
        try:
            transport.start()
        except Exception:
            pass  # lifecycle not under test here
        finally:
            transport.stop()
        assert os.environ["no_proxy"] == "foo.example.com"
        assert os.environ["NO_PROXY"] == "foo.example.com"
        transport2 = WebSocketGossipTransport(alice_identity, port=0)
        try:
            transport2.start()
        except Exception:
            transport2.stop()
            raise
        transport2.stop()
        assert os.environ["no_proxy"] == "foo.example.com"
        assert os.environ["NO_PROXY"] == "foo.example.com"


# ─────────────────── adversarial review round 7 ───────────────────


class TestInterop:
    def test_shim_signatures_verify_through_the_real_verifier(self, alice_identity, tmp_path):
        """Interop pin: messages signed by the adapter's shim channel must
        verify through gossip's own `_verify_msg_signature` exactly like
        TeamChannel-signed messages — payload shape is byte-compatible."""

        from nth_dao.channel import TeamChannel
        from nth_dao.gossip import _verify_msg_signature
        from nth_dao.delivery.transports.websocket_gossip import _EnvelopeChannel

        real_channel = TeamChannel(tmp_path, str(alice_identity.agent_id),
                                   identity=alice_identity)
        real_msg = real_channel.send(content="chat", scope="team")
        shim_msg = _EnvelopeChannel(alice_identity).send(content="chat", scope="team")

        assert set(real_msg.to_dict()) == set(shim_msg.to_dict())
        assert _verify_msg_signature(real_msg.to_dict(), real_msg.sig,
                                     alice_identity.pubkey_hex) is True
        assert _verify_msg_signature(shim_msg.to_dict(), shim_msg.sig,
                                     alice_identity.pubkey_hex) is True

    def test_deeply_nested_content_never_escapes_the_callback(self, bob_transport_factory):
        """RecursionError from a hostile content blob must not escape the
        gossip callback (it would otherwise kill the node's handler task)."""

        bob = bob_transport_factory("127.0.0.1", None)
        deep = "[" * 100_000 + "]" * 100_000
        bob._on_gossip_message({"content": deep}, relay_peer_id="")
        bob._on_gossip_message({"content": "ok"}, relay_peer_id="")
        assert bob.poll() == []

    def test_duplicate_bind_fails_cleanly_without_thread_leak(self, alice_transport, alice_identity):
        """A second transport on the same port must raise a clean
        GossipTransportError and leave no loop thread behind."""

        import threading

        from nth_dao.delivery.transports.websocket_gossip import (
            GossipTransportError,
            WebSocketGossipTransport,
        )

        host, port = alice_transport.url.replace("ws://", "").split(":")
        second = WebSocketGossipTransport(alice_identity, host=host, port=int(port))
        with pytest.raises(GossipTransportError):
            second.start()
        assert second._thread is None
        assert threading.active_count() < 40  # no thread accumulation

    def test_unsignable_identity_rejected_at_start(self, tmp_path):
        from nth_dao.identity import AgentIdentity, AgentID
        from nth_dao.delivery.transports.websocket_gossip import (
            GossipTransportError,
            WebSocketGossipTransport,
        )

        pubkeyless = AgentIdentity.generate(label="tmp")
        verify_only = AgentIdentity(
            agent_id=AgentID.from_pubkey(pubkeyless.pubkey_hex),
            label="nosign",
            _signing_key=None,
            _verify_key=bytes.fromhex(pubkeyless.pubkey_hex),
        )
        transport = WebSocketGossipTransport(verify_only, port=0)
        with pytest.raises(GossipTransportError, match="identity"):
            transport.start()

    def test_send_unsigned_envelope_rejected_client_side(self, alice_identity, alice_transport):
        """Both real transports validate envelopes BEFORE the wire (same
        contract as the file-bundle transport) — an unsigned envelope must
        be refused locally instead of being broadcast and dropped remotely."""

        envelope = _envelope(alice_identity)
        envelope.signature = ""
        result = alice_transport.send(envelope)
        assert not result.accepted
        assert "invalid-envelope" in result.error_code


class TestInboundDropCounter:
    def test_dropped_inbound_counts_flood_losses(self, alice_identity, bob_transport_factory):
        """Round-8 AF: flood drops are observable via dropped_inbound."""

        from nth_dao.delivery.transports import websocket_gossip as wg

        bob = bob_transport_factory("127.0.0.1", None)
        for i in range(wg._INBOUND_QUEUE_SIZE + 25):
            envelope = _envelope(alice_identity, payload={"n": i})
            bob._on_gossip_message(
                {"content": json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":"))},
                relay_peer_id="",
            )
        assert bob.dropped_inbound == 25
