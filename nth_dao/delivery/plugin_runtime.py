"""Bridge signed delivery envelopes through the governed PluginHost transport.

This is the single control-plane bridge between ``nth_dao.delivery`` and the
language-neutral ``org.nth-dao.transport.delivery`` capability. It preserves
the Host's revocable binding and InvocationAuthority checks while composing
the durable envelope outbox/inbox around a provider's leased transport queue.

Receive ordering is deliberate: every leased item is first accepted into the
durable DeliveryInbox, then the complete provider batch is acknowledged. A
crash before transport acknowledgement redelivers the same lease; the Inbox
turns that into an idempotent duplicate. A crash after acknowledgement is safe
because the envelope is already durable locally.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import time
from typing import Any, Mapping, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import DeliveryAck
from nth_dao.delivery.envelope import (
    TransportEnvelope,
    TransportEnvelopeRejected,
    validate_envelope,
)
from nth_dao.delivery.inbox import DeliveryInbox, InboxDecision
from nth_dao.delivery.outbox import (
    OUTBOX_ATTEMPT_ERROR,
    OUTBOX_ATTEMPT_REJECTED,
    OUTBOX_ATTEMPT_SENT,
    OUTBOX_STATE_DELIVERED,
    DurableOutbox,
    OutboxRecord,
)
from nth_dao.delivery.transports.base import SendResult
from nth_dao.plugins.host import (
    InvocationAuthority,
    PluginHostError,
    ProviderBinding,
)
from nth_dao.plugins.schema import PluginSchemaError
from nth_dao.plugins.transport import (
    TRANSPORT_CAPABILITY_ID,
    TRANSPORT_MAX_BATCH_SIZE,
    TRANSPORT_MAX_LEASE_MS,
    TransportOperationError,
    transport_envelope_digest,
)


RouteResolver = Callable[[str], str]
Clock = Callable[[], int]

_TRANSIENT_INBOX_REJECTIONS = frozenset(
    {
        "authorization callback failed",
        "inbox replay cache is full of unprocessed envelopes",
    }
)


class PluginDeliveryRuntimeError(RuntimeError):
    """Raised when Host/provider state prevents an honest delivery outcome."""


@dataclass(frozen=True)
class PluginReceiveResult:
    """One durable receive operation and its provider acknowledgement state."""

    decisions: tuple[InboxDecision, ...]
    found: bool
    transport_acknowledged: bool
    replayed: bool


class PluginDeliveryRuntime:
    """Durable delivery engine over one revocable PluginHost binding."""

    def __init__(
        self,
        *,
        binding: ProviderBinding,
        authority: InvocationAuthority,
        route_resolver: RouteResolver,
        outbox: DurableOutbox,
        inbox: DeliveryInbox,
        clock: Optional[Clock] = None,
    ) -> None:
        if not isinstance(binding, ProviderBinding):
            raise TypeError("binding must be a PluginHost ProviderBinding")
        if binding.contract.capability_id != TRANSPORT_CAPABILITY_ID:
            raise ValueError("binding does not provide the delivery transport capability")
        if not isinstance(authority, InvocationAuthority):
            raise TypeError("authority must be an InvocationAuthority")
        if TRANSPORT_CAPABILITY_ID not in authority.capability_ids:
            raise ValueError("authority does not include the delivery capability")
        if not callable(route_resolver):
            raise TypeError("route_resolver must be callable")
        if not isinstance(outbox, DurableOutbox):
            raise TypeError("outbox must be a DurableOutbox")
        if not isinstance(inbox, DeliveryInbox):
            raise TypeError("inbox must be a DeliveryInbox")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._binding = binding
        self._authority = authority
        self._route_resolver = route_resolver
        self.outbox = outbox
        self.inbox = inbox
        self._clock = clock or (lambda: int(time.time() * 1_000))
        self._transport_name = binding.plugin_id

    def submit(self, envelope: TransportEnvelope) -> SendResult:
        """Durably enqueue and submit one envelope through PluginHost."""

        now_ms = self._now_ms()
        ok, reason = validate_envelope(
            envelope,
            now_ms=now_ms,
            require_signature=True,
        )
        if not ok:
            return SendResult(accepted=False, error_code=f"invalid-envelope: {reason}")
        record = self.outbox.enqueue(envelope, now_ms=now_ms)
        if record.is_terminal:
            return SendResult(
                accepted=record.state == OUTBOX_STATE_DELIVERED,
                error_code="" if record.state == OUTBOX_STATE_DELIVERED else "outbox-terminal",
            )
        encoded = canonical_json(envelope.to_dict()).decode("utf-8")
        try:
            destination_route = self._route_resolver(envelope.recipient)
            response = self._binding.invoke(
                {
                    "operation": "send",
                    "delivery_id": envelope.message_id,
                    "destination_route_id": destination_route,
                    "envelope_json": encoded,
                    "envelope_sha256": transport_envelope_digest(encoded),
                    "expires_at_ms": envelope.expires_at_ms,
                },
                authority=self._authority,
            )
        except TransportOperationError as exc:
            outcome = OUTBOX_ATTEMPT_ERROR if exc.retryable else OUTBOX_ATTEMPT_REJECTED
            self._record_attempt(record, outcome=outcome, error_code=exc.code, at_ms=now_ms)
            return SendResult(accepted=False, error_code=exc.code)
        except (PluginHostError, PluginSchemaError, TypeError, ValueError) as exc:
            self._record_attempt(
                record,
                outcome=OUTBOX_ATTEMPT_ERROR,
                error_code="plugin-invocation-failed",
                at_ms=now_ms,
            )
            raise PluginDeliveryRuntimeError(
                f"delivery transport invocation failed: {exc}"
            ) from exc
        accepted = response.get("accepted") is True
        self._record_attempt(
            record,
            outcome=OUTBOX_ATTEMPT_SENT if accepted else OUTBOX_ATTEMPT_ERROR,
            error_code="" if accepted else "provider-rejected",
            at_ms=now_ms,
        )
        return SendResult(
            accepted=accepted,
            error_code="" if accepted else "provider-rejected",
        )

    def receive(
        self,
        *,
        receive_id: str,
        max_items: int = 16,
        lease_ms: int = 30_000,
    ) -> PluginReceiveResult:
        """Lease a batch, persist every decision, then acknowledge the lease."""

        if isinstance(max_items, bool) or not isinstance(max_items, int):
            raise TypeError("max_items must be an integer")
        if not 1 <= max_items <= TRANSPORT_MAX_BATCH_SIZE:
            raise ValueError(
                f"max_items must be within [1, {TRANSPORT_MAX_BATCH_SIZE}]"
            )
        if isinstance(lease_ms, bool) or not isinstance(lease_ms, int):
            raise TypeError("lease_ms must be an integer")
        if not 1 <= lease_ms <= TRANSPORT_MAX_LEASE_MS:
            raise ValueError(f"lease_ms must be within [1, {TRANSPORT_MAX_LEASE_MS}]")
        try:
            response = self._binding.invoke(
                {
                    "operation": "receive",
                    "receive_id": receive_id,
                    "limit": max_items,
                    "lease_ms": lease_ms,
                },
                authority=self._authority,
            )
            if response["found"] is not True:
                return PluginReceiveResult(
                    decisions=(),
                    found=False,
                    transport_acknowledged=False,
                    replayed=bool(response["replayed"]),
                )
            decisions = tuple(
                self._persist_transport_item(item) for item in response["items"]
            )
            if any(
                not decision.accepted
                and not decision.duplicate
                and decision.reason in _TRANSIENT_INBOX_REJECTIONS
                for decision in decisions
            ):
                return PluginReceiveResult(
                    decisions=decisions,
                    found=True,
                    transport_acknowledged=False,
                    replayed=bool(response["replayed"]),
                )
            acknowledgement = self._binding.invoke(
                {
                    "operation": "ack",
                    "receive_id": response["receive_id"],
                    "lease_id": response["lease_id"],
                    "batch_sha256": response["batch_sha256"],
                },
                authority=self._authority,
            )
        except (TransportOperationError, PluginHostError, PluginSchemaError) as exc:
            raise PluginDeliveryRuntimeError(
                f"delivery transport receive failed: {exc}"
            ) from exc
        if acknowledgement.get("acknowledged") is not True:
            raise PluginDeliveryRuntimeError("delivery transport did not acknowledge the lease")
        return PluginReceiveResult(
            decisions=decisions,
            found=True,
            transport_acknowledged=True,
            replayed=bool(response["replayed"]),
        )

    def apply_ack(self, ack: DeliveryAck) -> OutboxRecord:
        """Apply a receiver-signed delivery acknowledgement to the outbox."""

        return self.outbox.handle_ack(ack, now_ms=self._now_ms())

    def _persist_transport_item(self, item: Mapping[str, Any]) -> InboxDecision:
        encoded = item["envelope_json"]
        if transport_envelope_digest(encoded) != item["envelope_sha256"]:
            raise PluginDeliveryRuntimeError(
                "provider envelope digest changed after Host validation"
            )
        try:
            candidate = TransportEnvelope.from_dict(json.loads(encoded))
        except (json.JSONDecodeError, TransportEnvelopeRejected, TypeError, ValueError):
            candidate = None
        if candidate is not None:
            if candidate.message_id != item["delivery_id"]:
                raise PluginDeliveryRuntimeError(
                    "provider delivery_id does not match the signed envelope"
                )
            if candidate.expires_at_ms != item["expires_at_ms"]:
                raise PluginDeliveryRuntimeError(
                    "provider expiry does not match the signed envelope"
                )
        decision = self.inbox.accept(encoded, now_ms=self._now_ms())
        if (
            decision.envelope_sha256
            and decision.envelope_sha256 != f"sha256:{item['envelope_sha256']}"
        ):
            raise PluginDeliveryRuntimeError(
                "inbox envelope digest does not match provider bytes"
            )
        return decision

    def _record_attempt(
        self,
        record: OutboxRecord,
        *,
        outcome: str,
        error_code: str,
        at_ms: int,
    ) -> None:
        self.outbox.record_attempt(
            record.message_id,
            transport=self._transport_name,
            outcome=outcome,
            error_code=error_code,
            at_ms=at_ms,
        )

    def _now_ms(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise PluginDeliveryRuntimeError("delivery clock must return positive integer ms")
        return value


__all__ = [
    "PluginDeliveryRuntime",
    "PluginDeliveryRuntimeError",
    "PluginReceiveResult",
]
