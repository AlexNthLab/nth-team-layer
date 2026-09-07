"""nth_dao.delivery — transport-agnostic signed envelope delivery.

The delivery layer is the common protocol spine described in
``docs/architecture/DELIVERY_LAYER.md``: every domain event travels as a
signed ``TransportEnvelope`` through pluggable transports, is queued in a
durable outbox, is validated by a fail-closed inbox, and is routed by
policy rather than a fixed fallback order.

Boundary rules (never violated by this layer):

* Transports move opaque canonical-JSON envelopes. They never grant
  authority, verify business semantics, or rewrite signed fields.
* The inbox validates size, version, signature, TTL, nonce, and
  authorization BEFORE anything reaches the business layer.
* Message identity is content-addressed; receivers are idempotent by
  ``message_id`` and their replay cache survives process restarts.
"""

from nth_dao.delivery.envelope import (
    DEFAULT_HOP_LIMIT,
    ENVELOPE_PROTOCOL,
    ENVELOPE_VERSION,
    MAX_ENVELOPE_BYTES,
    MAX_HOP_LIMIT,
    MAX_PAYLOAD_BYTES,
    MAX_PAYLOAD_DEPTH,
    MAX_TTL_MS,
    TransportEnvelope,
    TransportEnvelopeRejected,
    envelope_digest,
    forward_envelope,
    new_nonce,
    sign_envelope,
    validate_envelope,
)
from nth_dao.delivery.acknowledgement import (
    DeliveryAck,
    DeliveryAckRejected,
    sign_ack,
    validate_ack,
)
from nth_dao.delivery.inbox import DeliveryInbox, InboxDecision
from nth_dao.delivery.outbox import DurableOutbox, OutboxRecord
from nth_dao.delivery.policy import (
    CENTRALIZED_POLICY,
    DECENTRALIZED_POLICY,
    OFFLINE_POLICY,
    RoutePolicy,
    RoutePolicyError,
)
from nth_dao.delivery.router import (
    DeliveryRouter,
    ReceivedEnvelope,
    RouteAttempt,
    RoutingResult,
)
from nth_dao.delivery.plugin_runtime import (
    PluginDeliveryRuntime,
    PluginDeliveryRuntimeError,
    PluginReceiveResult,
)

__all__ = [
    "CENTRALIZED_POLICY",
    "DECENTRALIZED_POLICY",
    "DEFAULT_HOP_LIMIT",
    "ENVELOPE_PROTOCOL",
    "ENVELOPE_VERSION",
    "MAX_ENVELOPE_BYTES",
    "MAX_HOP_LIMIT",
    "MAX_PAYLOAD_BYTES",
    "MAX_PAYLOAD_DEPTH",
    "MAX_TTL_MS",
    "OFFLINE_POLICY",
    "DeliveryAck",
    "DeliveryAckRejected",
    "DeliveryInbox",
    "DeliveryRouter",
    "DurableOutbox",
    "InboxDecision",
    "OutboxRecord",
    "PluginDeliveryRuntime",
    "PluginDeliveryRuntimeError",
    "PluginReceiveResult",
    "ReceivedEnvelope",
    "RouteAttempt",
    "RoutePolicy",
    "RoutePolicyError",
    "RoutingResult",
    "TransportEnvelope",
    "TransportEnvelopeRejected",
    "envelope_digest",
    "forward_envelope",
    "new_nonce",
    "sign_ack",
    "sign_envelope",
    "validate_ack",
    "validate_envelope",
]
