"""Transport implementations for the delivery layer.

Every transport implements :class:`nth_dao.delivery.transports.base.Transport`
and is registered into a :class:`nth_dao.delivery.router.DeliveryRouter`.
New transports (WebSocket gossip, HTTPS federation, Nostr, BLE, Courier)
plug in here without touching the envelope, inbox, or outbox contracts.
"""

from nth_dao.delivery.transports.base import (
    PRIVACY_LOCAL,
    PRIVACY_PEER,
    PRIVACY_PUBLIC_RELAY,
    SendResult,
    Transport,
    TransportCapabilities,
    TransportHealth,
    monotonic_ms,
)
from nth_dao.delivery.transports.loopback import (
    MODE_HUB,
    MODE_MESH,
    LoopbackEndpoint,
    LoopbackWire,
)

__all__ = [
    "MODE_HUB",
    "MODE_MESH",
    "PRIVACY_LOCAL",
    "PRIVACY_PEER",
    "PRIVACY_PUBLIC_RELAY",
    "LoopbackEndpoint",
    "LoopbackWire",
    "SendResult",
    "Transport",
    "TransportCapabilities",
    "TransportHealth",
    "monotonic_ms",
]
