"""Governed PluginHost bridge tests for the durable delivery runtime."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.outbox import OUTBOX_STATE_DELIVERED, DurableOutbox
from nth_dao.delivery.plugin_runtime import (
    PluginDeliveryRuntime,
    PluginDeliveryRuntimeError,
)
from nth_dao.identity import AgentIdentity
from nth_dao.plugins.builtin.loopback_transport import (
    loopback_route_id,
    register_loopback_transport,
)
from nth_dao.plugins.host import (
    InvocationAuthority,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
)
from nth_dao.plugins.transport import (
    TRANSPORT_CAPABILITY_ID,
    transport_envelope_digest,
)

pytest.importorskip("nacl")


def _authority(principal: str, *routes: str) -> InvocationAuthority:
    return InvocationAuthority(
        principal=principal,
        capability_ids=frozenset({TRANSPORT_CAPABILITY_ID}),
        resource_ids=frozenset(routes),
    )


def _enabled_binding(tmp_path: Path):
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    manifest = register_loopback_transport(host)
    host.authorize(manifest.plugin_id, set())
    return host, host.enable(manifest.plugin_id)[0]


def _runtime(
    tmp_path: Path,
    *,
    name: str,
    identity: AgentIdentity,
    binding,
    routes: tuple[str, ...] = (),
    authorize=None,
) -> PluginDeliveryRuntime:
    now_ms = int(time.time() * 1_000)
    return PluginDeliveryRuntime(
        binding=binding,
        authority=_authority(identity.as_did(), *routes),
        route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / name / "outbox", clock=lambda: now_ms),
        inbox=DeliveryInbox(
            tmp_path / name / "inbox",
            authorize=authorize,
            clock=lambda: now_ms,
        ),
        clock=lambda: now_ms,
    )


def _envelope(sender: AgentIdentity, recipient: str):
    now_ms = int(time.time() * 1_000)
    return sign_envelope(
        sender,
        kind="chat.message",
        recipient=recipient,
        payload={"body": "hello"},
        created_at_ms=now_ms,
        expires_at_ms=now_ms + 60_000,
    )


def test_plugin_runtime_persists_before_transport_ack_and_applies_signed_ack(
    tmp_path: Path,
) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    alice_runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
        routes=(bob_route,),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (item.recipient == bob.as_did(), "wrong recipient"),
    )
    envelope = _envelope(alice, bob.as_did())

    assert alice_runtime.submit(envelope).accepted is True
    received = bob_runtime.receive(receive_id="receive-1")

    assert received.found is True
    assert received.transport_acknowledged is True
    assert received.decisions[0].accepted is True
    assert bob_runtime.inbox.pending()[0].message_id == envelope.message_id

    ack = sign_ack(
        bob,
        message_id=envelope.message_id,
        envelope_sha256=received.decisions[0].envelope_sha256,
        received_at_ms=int(time.time() * 1_000),
    )
    delivered = alice_runtime.apply_ack(ack)
    assert delivered.state == OUTBOX_STATE_DELIVERED
    assert delivered.delivered_by == bob.as_did()

    empty = bob_runtime.receive(receive_id="receive-2")
    assert empty.found is False
    assert empty.transport_acknowledged is False
    assert empty.decisions == ()


def test_plugin_runtime_recovers_after_crash_window_before_transport_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    alice_runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
        routes=(bob_route,),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (True, "ok"),
    )
    envelope = _envelope(alice, bob.as_did())
    assert alice_runtime.submit(envelope).accepted is True

    original_invoke = host.invoke

    def fail_ack_once(binding_arg, payload, *, authority):
        if payload.get("operation") == "ack":
            raise PluginInvocationError("simulated crash before provider ack")
        return original_invoke(binding_arg, payload, authority=authority)

    monkeypatch.setattr(host, "invoke", fail_ack_once)
    with pytest.raises(PluginDeliveryRuntimeError, match="receive failed"):
        bob_runtime.receive(receive_id="receive-crash")
    assert bob_runtime.inbox.seen(envelope.message_id) is True

    monkeypatch.setattr(host, "invoke", original_invoke)
    replay = bob_runtime.receive(receive_id="receive-crash")
    assert replay.replayed is True
    assert replay.transport_acknowledged is True
    assert replay.decisions[0].duplicate is True


def test_plugin_runtime_keeps_lease_for_transient_inbox_failure(
    tmp_path: Path,
) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    alice_runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
        routes=(bob_route,),
    )
    allow = False

    def authorize(_):
        if not allow:
            raise RuntimeError("authorization database unavailable")
        return True, "ok"

    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=authorize,
    )
    envelope = _envelope(alice, bob.as_did())
    assert alice_runtime.submit(envelope).accepted is True

    first = bob_runtime.receive(receive_id="receive-transient")
    assert first.transport_acknowledged is False
    assert first.decisions[0].reason == "authorization callback failed"

    allow = True
    second = bob_runtime.receive(receive_id="receive-transient")
    assert second.replayed is True
    assert second.transport_acknowledged is True
    assert second.decisions[0].accepted is True


def test_plugin_runtime_rejects_routes_outside_host_authority(tmp_path: Path) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
    )
    envelope = _envelope(alice, bob.as_did())

    with pytest.raises(PluginDeliveryRuntimeError, match="invocation failed"):
        runtime.submit(envelope)

    record = runtime.outbox.get(envelope.message_id)
    assert record is not None
    assert record.attempts[-1].error_code == "plugin-invocation-failed"


def test_plugin_runtime_observes_host_binding_revocation(tmp_path: Path) -> None:
    host, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
        routes=(bob_route,),
    )
    assert host.disable(binding.plugin_id) is True

    with pytest.raises(PluginDeliveryRuntimeError, match="invocation failed"):
        runtime.submit(_envelope(alice, bob.as_did()))


def test_plugin_runtime_does_not_ack_provider_id_substitution(tmp_path: Path) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    envelope = _envelope(alice, bob.as_did())
    encoded = canonical_json(envelope.to_dict()).decode("utf-8")
    binding.invoke(
        {
            "operation": "send",
            "delivery_id": "substituted-delivery-id",
            "destination_route_id": bob_route,
            "envelope_json": encoded,
            "envelope_sha256": transport_envelope_digest(encoded),
            "expires_at_ms": envelope.expires_at_ms,
        },
        authority=_authority(alice.as_did(), bob_route),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (True, "ok"),
    )

    with pytest.raises(PluginDeliveryRuntimeError, match="delivery_id"):
        bob_runtime.receive(receive_id="receive-substitution")

    assert bob_runtime.inbox.seen(envelope.message_id) is False


def test_plugin_runtime_does_not_ack_provider_expiry_substitution(
    tmp_path: Path,
) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    envelope = _envelope(alice, bob.as_did())
    encoded = canonical_json(envelope.to_dict()).decode("utf-8")
    binding.invoke(
        {
            "operation": "send",
            "delivery_id": envelope.message_id,
            "destination_route_id": bob_route,
            "envelope_json": encoded,
            "envelope_sha256": transport_envelope_digest(encoded),
            "expires_at_ms": envelope.expires_at_ms + 1_000,
        },
        authority=_authority(alice.as_did(), bob_route),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (True, "ok"),
    )

    with pytest.raises(PluginDeliveryRuntimeError, match="expiry"):
        bob_runtime.receive(receive_id="receive-expiry-substitution")

    assert bob_runtime.inbox.seen(envelope.message_id) is False


def test_plugin_runtime_acks_permanently_invalid_transport_items(
    tmp_path: Path,
) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    encoded = canonical_json({"not": "a delivery envelope"}).decode("utf-8")
    binding.invoke(
        {
            "operation": "send",
            "delivery_id": "invalid-envelope-1",
            "destination_route_id": bob_route,
            "envelope_json": encoded,
            "envelope_sha256": transport_envelope_digest(encoded),
            "expires_at_ms": int(time.time() * 1_000) + 60_000,
        },
        authority=_authority(alice.as_did(), bob_route),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (True, "ok"),
    )

    result = bob_runtime.receive(receive_id="receive-invalid")
    assert result.transport_acknowledged is True
    assert result.decisions[0].accepted is False
    assert result.decisions[0].reason.startswith("structure:")
    assert bob_runtime.receive(receive_id="receive-after-invalid").found is False
