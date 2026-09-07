"""Phase-1 integration: real transports inside the delivery router.

End-to-end over REAL wire (localhost HTTP / WebSocket), no mocks:

    alice.outbox.enqueue → DeliveryRouter.send(FederationTransport)
    → bob FederationIngestServer → bob DeliveryInbox → bob signs ACK
    → ACK envelope back over the wire → alice.inbox → unwrap
    → alice.outbox.handle_ack → DELIVERED

and the same flow over the WebSocket gossip mesh, plus router-policy
selection between the two real transports.
"""

from __future__ import annotations

import time

import pytest

from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import (
    envelope_digest,
    sign_envelope,
)
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.outbox import OUTBOX_STATE_DELIVERED, OUTBOX_STATE_QUEUED, DurableOutbox
from nth_dao.delivery.policy import DECENTRALIZED_POLICY, RoutePolicy
from nth_dao.delivery.router import DeliveryRouter
from nth_dao.delivery.transports.federation import (
    FederationIngestServer,
    FederationTransport,
    ack_from_envelope,
)
from nth_dao.delivery.transports.loopback import MODE_MESH, LoopbackEndpoint, LoopbackWire
from nth_dao.delivery.transports.websocket_gossip import WebSocketGossipTransport

pytest.importorskip("nacl")
pytest.importorskip("websockets")

NOW_MS = 1_750_000_000_000


@pytest.fixture()
def alice_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def bob_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="bob")


def _wait_until(predicate, timeout=10.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _sign_ack_envelope(receiver_identity, ack, *, recipient_did, created_at_ms):
    """The receiver wraps its signed ACK as an ordinary envelope."""

    return sign_envelope(
        receiver_identity,
        kind="delivery.ack",
        recipient=recipient_did,
        payload={"ack": ack.to_dict()},
        created_at_ms=created_at_ms,
        expires_at_ms=created_at_ms + 60_000,
    )


class TestFederationEndToEnd:
    """Two nodes, two real HTTP ingest servers, ACK round trip."""

    def test_full_ack_round_trip_over_http(self, tmp_path, alice_identity, bob_identity):
        alice_did = alice_identity.as_did()
        bob_did = bob_identity.as_did()

        # ── both nodes: outbox + inbox + ingest front door ──
        alice_outbox = DurableOutbox(tmp_path / "alice", clock=lambda: NOW_MS)
        alice_inbox = DeliveryInbox(tmp_path / "alice-in", clock=lambda: NOW_MS)
        alice_server = FederationIngestServer(alice_inbox, host="127.0.0.1", port=0)
        alice_server.start()

        bob_outbox = DurableOutbox(tmp_path / "bob", clock=lambda: NOW_MS)
        bob_inbox = DeliveryInbox(tmp_path / "bob-in", clock=lambda: NOW_MS + 1_000)
        bob_server = FederationIngestServer(bob_inbox, host="127.0.0.1", port=0)
        bob_server.start()

        try:
            # ── alice's router carries her outbound federation traffic ──
            alice_router = DeliveryRouter(clock=lambda: NOW_MS)
            alice_router.register(
                FederationTransport(
                    recipient_urls={bob_did: bob_server.url}, name="fed-to-bob"
                )
            )

            envelope = sign_envelope(
                alice_identity,
                kind="mission.announcement",
                recipient=bob_did,
                payload={"title": "ship payments v2"},
                created_at_ms=NOW_MS,
                expires_at_ms=NOW_MS + 120_000,
            )
            record = alice_outbox.enqueue(envelope)
            assert record.state == OUTBOX_STATE_QUEUED

            # 1. routed send over real HTTP
            result = alice_router.send(envelope, DECENTRALIZED_POLICY)
            assert result.sent_via == ["fed-to-bob"]

            # 2. bob's inbox received and validated it
            assert _wait_until(lambda: bob_inbox.seen(envelope.message_id))
            accepted = bob_inbox.accept(envelope, now_ms=NOW_MS + 1_500)
            # first arrival was consumed by the ingest; redelivery is dup
            assert accepted.duplicate

            # 3. bob signs the ACK and sends it back through his own router
            bob_router = DeliveryRouter(clock=lambda: NOW_MS)
            bob_router.register(
                FederationTransport(
                    recipient_urls={alice_did: alice_server.url}, name="fed-to-alice"
                )
            )
            ack = sign_ack(
                bob_identity,
                message_id=envelope.message_id,
                envelope_sha256=envelope_digest(envelope),
                received_at_ms=NOW_MS + 2_000,
            )
            ack_envelope = _sign_ack_envelope(
                bob_identity, ack, recipient_did=alice_did, created_at_ms=NOW_MS + 2_100
            )
            bob_outbox.enqueue(ack_envelope)
            bob_result = bob_router.send(ack_envelope, DECENTRALIZED_POLICY)
            assert bob_result.sent_via == ["fed-to-alice"]

            # 4. alice unwraps the ACK and closes her outbox record
            assert _wait_until(lambda: alice_inbox.seen(ack_envelope.message_id))
            unwrapped = ack_from_envelope(ack_envelope)
            final = alice_outbox.handle_ack(unwrapped, now_ms=NOW_MS + 3_000)
            assert final.state == OUTBOX_STATE_DELIVERED
            assert final.delivered_by == bob_did
        finally:
            alice_server.stop()
            bob_server.stop()

    def test_unauthorized_envelope_rejected_at_ingest(self, tmp_path, alice_identity, bob_identity):
        """The authorize hook runs inside the ingest pipeline: a hostile
        sender with a VALID signature but no authorization gets 422 and the
        sender sees peers-unreachable."""

        bob_inbox = DeliveryInbox(
            tmp_path / "bob-in",
            clock=lambda: NOW_MS + 1_000,
            authorize=lambda env: (env.sender_did == bob_identity.as_did(), "sender not allowlisted"),
        )
        server = FederationIngestServer(bob_inbox, host="127.0.0.1", port=0)
        server.start()
        try:
            transport = FederationTransport(
                recipient_urls={bob_identity.as_did(): server.url}
            )
            hostile = sign_envelope(
                alice_identity,  # valid signature, but not allowlisted
                kind="channel.message",
                recipient=bob_identity.as_did(),
                payload={"body": "unsolicited"},
                created_at_ms=NOW_MS,
                expires_at_ms=NOW_MS + 120_000,
            )
            result = transport.send(hostile)
            assert not result.accepted
            assert result.error_code == "peers-unreachable"
            assert bob_inbox.entry_count() == 0
        finally:
            server.stop()


class TestGossipEndToEnd:
    """Two real GossipNodes, full pipeline including the ACK return leg."""

    def test_full_ack_round_trip_over_gossip(self, tmp_path, alice_identity, bob_identity):
        bob_did = bob_identity.as_did()
        alice_did = alice_identity.as_did()

        alice_outbox = DurableOutbox(tmp_path / "alice", clock=lambda: NOW_MS)
        alice_inbox = DeliveryInbox(tmp_path / "alice-in", clock=lambda: NOW_MS)
        alice_transport = WebSocketGossipTransport(
            alice_identity,
            port=0,
            trusted_pubkeys={str(bob_identity.agent_id): bob_identity.pubkey_hex},
        )
        alice_transport.start()

        bob_inbox = DeliveryInbox(tmp_path / "bob-in", clock=lambda: NOW_MS + 1_000)
        bob_transport = WebSocketGossipTransport(
            bob_identity,
            port=0,
            trusted_pubkeys={str(alice_identity.agent_id): alice_identity.pubkey_hex},
        )
        bob_transport.start()
        try:
            import asyncio

            connect = asyncio.run_coroutine_threadsafe(
                bob_transport._node.connect(alice_transport.url), bob_transport._loop
            )
            assert connect.result(timeout=10.0) is True
            assert _wait_until(lambda: alice_transport.peer_count() >= 1)

            alice_router = DeliveryRouter(clock=lambda: NOW_MS)
            alice_router.register(alice_transport)

            envelope = sign_envelope(
                alice_identity,
                kind="mission.announcement",
                recipient=bob_did,
                payload={"title": "offline mission"},
                created_at_ms=NOW_MS,
                expires_at_ms=NOW_MS + 120_000,
            )
            alice_outbox.enqueue(envelope)
            result = alice_router.send(envelope, DECENTRALIZED_POLICY)
            assert result.sent_via == ["gossip-ws"]

            # bob receives over the wire and validates
            assert _wait_until(lambda: len(bob_transport._inbox) >= 1)
            received = bob_transport.poll()[0]
            decision = bob_inbox.accept(received, now_ms=NOW_MS + 1_500)
            assert decision.accepted, decision.reason

            # bob signs the ACK and pushes it back through his own transport
            bob_router = DeliveryRouter(clock=lambda: NOW_MS)
            bob_router.register(bob_transport)
            ack = sign_ack(
                bob_identity,
                message_id=envelope.message_id,
                envelope_sha256=envelope_digest(envelope),
                received_at_ms=NOW_MS + 2_000,
            )
            ack_envelope = _sign_ack_envelope(
                bob_identity, ack, recipient_did=alice_did, created_at_ms=NOW_MS + 2_100
            )
            assert bob_router.send(ack_envelope, DECENTRALIZED_POLICY).accepted

            # alice receives the ACK envelope, unwraps, closes the record
            assert _wait_until(lambda: len(alice_transport._inbox) >= 1)
            ack_received = alice_transport.poll()[0]
            assert alice_inbox.accept(ack_received, now_ms=NOW_MS + 3_000).accepted
            unwrapped = ack_from_envelope(ack_received)
            final = alice_outbox.handle_ack(unwrapped, now_ms=NOW_MS + 3_500)
            assert final.state == OUTBOX_STATE_DELIVERED
        finally:
            alice_transport.stop()
            bob_transport.stop()


class TestRouterPolicySelection:
    def test_router_picks_gossip_for_realtime_and_federation_for_offline(
        self, tmp_path, alice_identity
    ):
        """Both real transports registered; the policy decides — realtime
        decentralized policy routes to gossip, the offline-leaning policy to
        the (non-realtime) federation transport."""

        bob_server = FederationIngestServer(
            DeliveryInbox(tmp_path / "bob-in", clock=lambda: NOW_MS), host="127.0.0.1", port=0
        )
        bob_server.start()
        gossip = WebSocketGossipTransport(
            alice_identity,
            port=0,
            trusted_pubkeys={},
        )
        gossip.start()
        # a real gossip peer so the realtime route can actually accept
        gossip_peer = WebSocketGossipTransport(
            alice_identity, port=0, trusted_pubkeys={}
        )
        gossip_peer.start()
        import asyncio

        connect = asyncio.run_coroutine_threadsafe(
            gossip_peer._node.connect(gossip.url), gossip_peer._loop
        )
        assert connect.result(timeout=10.0) is True
        assert _wait_until(lambda: gossip.peer_count() >= 1)
        federation = FederationTransport(peer_urls=[bob_server.url], name="fed")
        try:
            router = DeliveryRouter(clock=lambda: NOW_MS)
            router.register(gossip)
            router.register(federation)

            envelope = sign_envelope(
                alice_identity,
                kind="channel.message",
                recipient="dao:core",
                payload={"body": "hi"},
                created_at_ms=NOW_MS,
                expires_at_ms=NOW_MS + 120_000,
            )
            realtime_policy = RoutePolicy(prefer_realtime=True, privacy_floor=1)
            offline_policy = RoutePolicy(prefer_realtime=False, privacy_floor=1)

            realtime = router.send(envelope, realtime_policy)
            offline = router.send(envelope, offline_policy)
            assert realtime.sent_via == ["gossip-ws"]
            assert offline.sent_via == ["fed"]
        finally:
            gossip.stop()
            gossip_peer.stop()
            bob_server.stop()

    def test_mixed_policy_falls_back_from_gossip_to_federation(
        self, tmp_path, alice_identity
    ):
        """Gossip with no connected peers refuses to send; the router falls
        back to the federation transport within one send() call."""

        bob_server = FederationIngestServer(
            DeliveryInbox(tmp_path / "bob-in", clock=lambda: NOW_MS), host="127.0.0.1", port=0
        )
        bob_server.start()
        gossip = WebSocketGossipTransport(alice_identity, port=0, trusted_pubkeys={})
        gossip.start()
        federation = FederationTransport(peer_urls=[bob_server.url], name="fed")
        try:
            router = DeliveryRouter(clock=lambda: NOW_MS)
            router.register(gossip)
            router.register(federation)
            envelope = sign_envelope(
                alice_identity,
                kind="channel.message",
                recipient="dao:core",
                payload={"body": "hi"},
                created_at_ms=NOW_MS,
                expires_at_ms=NOW_MS + 120_000,
            )
            result = router.send(envelope, RoutePolicy(copy_count=1, prefer_realtime=True))
            assert result.attempts[0].transport == "gossip-ws"
            assert result.sent_via == ["fed"]  # fallback over real HTTP
        finally:
            gossip.stop()
            bob_server.stop()


class TestLoopbackStillWired:
    def test_phase0_loopback_router_unchanged(self, alice_identity):
        router = DeliveryRouter(clock=lambda: NOW_MS)
        wire = LoopbackWire()
        receiver = LoopbackEndpoint(wire, "n1", mode=MODE_MESH)
        router.register(receiver)
        sender = LoopbackEndpoint(wire, "n2", mode=MODE_MESH)
        envelope = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"body": "hi"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        assert sender.send(envelope).accepted
        assert router.receive()[0].envelope.message_id == envelope.message_id
