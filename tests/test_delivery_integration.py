"""End-to-end delivery pipeline integration test.

Pins the whole Phase-0 spine together, per the integration design doc §5:

    alice.outbox.enqueue → router.send(mesh) → bob.poll → bob.inbox.accept
    → bob signs ACK → alice.outbox.handle_ack → delivered

Plus the centralized (hub) mode, the offline file-bundle mode, and the
hostile paths (duplicate / replay / tamper / expiry) at the pipeline level.
"""

from __future__ import annotations

import pytest

from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.outbox import OUTBOX_STATE_DELIVERED, DurableOutbox
from nth_dao.delivery.policy import DECENTRALIZED_POLICY, RoutePolicy
from nth_dao.delivery.router import DeliveryRouter
from nth_dao.delivery.transports.loopback import (
    MODE_HUB,
    MODE_MESH,
    LoopbackEndpoint,
    LoopbackWire,
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


class TestMeshPipeline:
    """Decentralized federation-broadcast mode, end to end."""

    def test_full_pipeline_mesh(self, tmp_path, alice_identity, bob_identity):
        bob_did = bob_identity.as_did()

        # ── alice: outbox + router with a mesh transport ──
        alice_outbox = DurableOutbox(
            tmp_path / "alice",
            clock=lambda: NOW_MS,
            authorize_ack=lambda ack, queued: (
                ack.receiver_did == bob_did and queued.recipient == "dao:core",
                "receiver is not authorized for this shared recipient",
            ),
        )
        alice_router = DeliveryRouter(clock=lambda: NOW_MS)
        alice_wire = LoopbackWire()
        alice_ep = LoopbackEndpoint(alice_wire, "alice", mode=MODE_MESH)
        alice_router.register(alice_ep)

        # ── bob: router + inbox with the receiving mesh endpoint ──
        bob_inbox = DeliveryInbox(
            tmp_path / "bob",
            clock=lambda: NOW_MS + 1_000,
            authorize=lambda env: (env.recipient in {"dao:core", bob_did}, "ok"),
        )
        bob_router = DeliveryRouter(clock=lambda: NOW_MS)
        bob_ep = LoopbackEndpoint(alice_wire, "bob", mode=MODE_MESH)
        bob_router.register(bob_ep)
        # one shared wire: alice_ep sends, bob_ep receives

        envelope = sign_envelope(
            alice_identity,
            kind="mission.announcement",
            recipient="dao:core",
            payload={"title": "ship payments v2"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )

        # 1. alice queues the signed envelope durably
        record = alice_outbox.enqueue(envelope)
        assert record.state == "queued"

        # 2. alice routes it over the mesh
        result = alice_router.send(envelope, DECENTRALIZED_POLICY)
        assert result.sent_via == ["loopback-alice"]

        # 3. alice records the transport attempt
        alice_outbox.record_attempt(
            envelope.message_id, transport="loopback-alice", outcome="sent", at_ms=NOW_MS
        )

        # 4. bob receives and validates fail-closed
        received = bob_router.receive()
        assert len(received) == 1
        decision = bob_inbox.accept(received[0].envelope, now_ms=NOW_MS + 1_500)
        assert decision.accepted, decision.reason

        # 5. bob signs the ACK binding the received bytes
        ack = sign_ack(
            bob_identity,
            message_id=decision.message_id,
            envelope_sha256=decision.envelope_sha256,
            received_at_ms=NOW_MS + 2_000,
        )

        # 6. alice applies the ACK: record is terminally delivered
        final = alice_outbox.handle_ack(ack, now_ms=NOW_MS + 2_500)
        assert final.state == OUTBOX_STATE_DELIVERED
        assert final.delivered_by == bob_did

        # 7. a redelivery of the same envelope is an idempotent drop
        second = bob_inbox.accept(received[0].envelope, now_ms=NOW_MS + 3_000)
        assert not second.accepted and second.duplicate

    def test_expired_envelope_rejected_end_to_end(self, tmp_path, alice_identity, bob_identity):
        bob_inbox = DeliveryInbox(tmp_path / "bob", clock=lambda: NOW_MS + 61_000)
        envelope = sign_envelope(
            alice_identity,
            kind="mission.announcement",
            recipient="dao:core",
            payload={"title": "late"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        decision = bob_inbox.accept(envelope, now_ms=NOW_MS + 61_000)
        assert not decision.accepted and "expired" in decision.reason

    def test_replayed_nonce_rejected_end_to_end(self, tmp_path, alice_identity):
        bob_inbox = DeliveryInbox(tmp_path / "bob", clock=lambda: NOW_MS)
        first = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"n": 1},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
            nonce="ReplayProbeNonce0123456789",
        )
        assert bob_inbox.accept(first, now_ms=NOW_MS).accepted
        replay = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"n": 2},
            created_at_ms=NOW_MS + 500,
            expires_at_ms=NOW_MS + 60_500,
            nonce="ReplayProbeNonce0123456789",
        )
        decision = bob_inbox.accept(replay, now_ms=NOW_MS + 1_000)
        assert not decision.accepted and decision.replayed

    def test_tampered_envelope_rejected_end_to_end(self, tmp_path, alice_identity):
        bob_inbox = DeliveryInbox(tmp_path / "bob", clock=lambda: NOW_MS)
        envelope = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"body": "legit"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        envelope.payload = {"body": "evil"}
        decision = bob_inbox.accept(envelope, now_ms=NOW_MS)
        assert not decision.accepted


class TestHubPipeline:
    """Centralized relay mode: the same ACK-terminal flow over a hub."""

    def test_full_pipeline_hub(self, tmp_path, alice_identity, bob_identity):
        bob_did = bob_identity.as_did()
        wire = LoopbackWire()
        # both parties connect to the same central queue
        alice_hub = LoopbackEndpoint(wire, "alice", mode=MODE_HUB, serve={bob_did})
        bob_hub = LoopbackEndpoint(wire, "bob", mode=MODE_HUB, serve={alice_identity.as_did()})

        alice_outbox = DurableOutbox(tmp_path / "alice", clock=lambda: NOW_MS)
        envelope = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient=bob_did,
            payload={"body": "private"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        alice_outbox.enqueue(envelope)
        sent = alice_hub.send(envelope)
        assert sent.accepted

        bob_inbox = DeliveryInbox(tmp_path / "bob", clock=lambda: NOW_MS + 1_000)
        for polled in bob_hub.poll():
            decision = bob_inbox.accept(polled, now_ms=NOW_MS + 1_500)
            assert decision.accepted, decision.reason
            ack = sign_ack(
                bob_identity,
                message_id=decision.message_id,
                envelope_sha256=decision.envelope_sha256,
                received_at_ms=NOW_MS + 2_000,
            )
            final = alice_outbox.handle_ack(ack, now_ms=NOW_MS + 2_500)
            assert final.state == OUTBOX_STATE_DELIVERED


class TestFileBundlePipeline:
    """Offline carry mode: USB-stick-shaped delivery, end to end."""

    def test_full_pipeline_file_bundle(self, tmp_path, alice_identity, bob_identity):
        from nth_dao.delivery.transports.file_bundle import FileBundleTransport

        bob_did = bob_identity.as_did()
        exchange = tmp_path / "usb-stick"
        sender = FileBundleTransport(
            exchange, alice_identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
        )
        envelope = sign_envelope(
            alice_identity,
            kind="mission.announcement",
            recipient="dao:core",
            payload={"title": "offline mission"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 86_400_000,
        )
        alice_outbox = DurableOutbox(
            tmp_path / "alice",
            clock=lambda: NOW_MS,
            authorize_ack=lambda ack, queued: (
                ack.receiver_did == bob_did and queued.recipient == "dao:core",
                "receiver is not authorized for this shared recipient",
            ),
        )
        alice_outbox.enqueue(envelope)
        assert sender.send(envelope).accepted

        bob_inbox = DeliveryInbox(tmp_path / "bob", clock=lambda: NOW_MS + 3_600_000)
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        for polled in receiver.poll():
            decision = bob_inbox.accept(polled, now_ms=NOW_MS + 3_600_000)
            assert decision.accepted, decision.reason
            ack = sign_ack(
                bob_identity,
                message_id=decision.message_id,
                envelope_sha256=decision.envelope_sha256,
                received_at_ms=NOW_MS + 3_600_000,
            )
            final = alice_outbox.handle_ack(ack, now_ms=NOW_MS + 3_600_000)
            assert final.state == OUTBOX_STATE_DELIVERED


class TestPolicyModes:
    def test_decentralized_policy_excludes_hub_transport(self, alice_identity):
        router = DeliveryRouter(clock=lambda: NOW_MS)
        wire = LoopbackWire()
        hub = LoopbackEndpoint(wire, "hub-node", mode=MODE_HUB, serve={"dao:core"})
        mesh = LoopbackEndpoint(wire, "mesh-node", mode=MODE_MESH)
        LoopbackEndpoint(wire, "mesh-peer", mode=MODE_MESH)  # a reachable mesh peer
        router.register(hub)
        router.register(mesh)
        envelope = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"body": "private-ish"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        result = router.send(envelope, DECENTRALIZED_POLICY)
        assert result.sent_via == ["loopback-mesh-node"]

    def test_user_selects_centralized_mode_by_allowlist(self, alice_identity):
        router = DeliveryRouter(clock=lambda: NOW_MS)
        wire = LoopbackWire()
        hub = LoopbackEndpoint(wire, "hub-node", mode=MODE_HUB, serve={"dao:core"})
        mesh = LoopbackEndpoint(wire, "mesh-node", mode=MODE_MESH)
        router.register(hub)
        router.register(mesh)
        envelope = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"body": "via relay"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        centralized = RoutePolicy(allowed_transports=("loopback-hub-node",))
        result = router.send(envelope, centralized)
        assert result.sent_via == ["loopback-hub-node"]
