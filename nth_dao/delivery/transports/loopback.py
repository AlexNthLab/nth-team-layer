"""In-process loopback transports: the two communication modes, testable.

* **mesh** (decentralized federation broadcast) — a send fans out a copy to
  every other mesh endpoint on the wire. Everyone receives everything; the
  receiving inbox filters by recipient and authorization. This is the
  bitchat-style controlled-flood model and the reference behavior for the
  future BLE/Nostr broadcast adapters.

* **hub** (centralized module) — a send is parked on the wire's central
  queue; each hub endpoint claims items whose recipient it serves. This is
  the "trusted relay" shape: the relay sees every unclaimed envelope, which
  is exactly why its privacy level is ``PRIVACY_PUBLIC_RELAY`` and a
  privacy-conscious policy can exclude it.

Both are loopback-only (same process) and exist so the router, outbox,
inbox, and policy semantics are testable without any network stack. Real
transports (WebSocket gossip, HTTPS federation, file bundles, later BLE and
Nostr) implement the same :class:`Transport` contract.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Dict, Iterable, List, Set

from nth_dao.delivery.envelope import TransportEnvelope
from nth_dao.delivery.transports.base import (
    PRIVACY_PEER,
    PRIVACY_PUBLIC_RELAY,
    SendResult,
    Transport,
    TransportCapabilities,
)

MODE_HUB = "hub"
MODE_MESH = "mesh"
_MODES = (MODE_HUB, MODE_MESH)

MAX_WIRE_QUEUE = 4_096


class LoopbackWireError(RuntimeError):
    pass


class LoopbackWire:
    """The shared medium connecting loopback endpoints in one process."""

    def __init__(self, name: str = "loopback") -> None:
        self.name = name
        self._endpoints: Dict[str, "LoopbackEndpoint"] = {}
        self._hub_queue: deque = deque()
        self._lock = threading.RLock()

    def attach(self, endpoint: "LoopbackEndpoint") -> None:
        with self._lock:
            if endpoint.endpoint_id in self._endpoints:
                raise LoopbackWireError(f"endpoint attached twice: {endpoint.endpoint_id}")
            self._endpoints[endpoint.endpoint_id] = endpoint

    def detach(self, endpoint_id: str) -> None:
        with self._lock:
            self._endpoints.pop(endpoint_id, None)

    def endpoint_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._endpoints)

    def _fanout_mesh(self, sender_id: str, envelope: TransportEnvelope) -> int:
        delivered = 0
        with self._lock:
            for endpoint_id, endpoint in self._endpoints.items():
                if endpoint_id == sender_id:
                    continue
                if endpoint.mode != MODE_MESH:
                    continue
                if len(endpoint._inbox) >= MAX_WIRE_QUEUE:
                    continue  # drop on overflow: loopback never blocks
                endpoint._inbox.append(envelope)
                delivered += 1
        return delivered

    def _park_on_hub(self, sender_id: str, envelope: TransportEnvelope) -> bool:
        with self._lock:
            if len(self._hub_queue) >= MAX_WIRE_QUEUE:
                return False
            self._hub_queue.append(envelope)
            return True

    def _claim_from_hub(self, served: Set[str], limit: int) -> List[TransportEnvelope]:
        claimed: List[TransportEnvelope] = []
        with self._lock:
            remaining: deque = deque()
            while self._hub_queue and len(claimed) < limit:
                envelope = self._hub_queue.popleft()
                if envelope.recipient in served:
                    claimed.append(envelope)
                else:
                    remaining.append(envelope)
            remaining.extend(self._hub_queue)
            self._hub_queue = remaining
        return claimed

    def hub_depth(self) -> int:
        with self._lock:
            return len(self._hub_queue)


class LoopbackEndpoint(Transport):
    """One node's view of the wire. Registers into a router as a Transport."""

    def __init__(
        self,
        wire: LoopbackWire,
        endpoint_id: str,
        *,
        mode: str = MODE_MESH,
        serve: Iterable[str] = (),
        realtime: bool = True,
    ) -> None:
        if mode not in _MODES:
            raise ValueError(f"mode must be one of {_MODES}")
        self.endpoint_id = endpoint_id
        self.mode = mode
        self._served: Set[str] = set(serve)
        self._inbox: deque = deque()
        self._wire = wire
        privacy = PRIVACY_PUBLIC_RELAY if mode == MODE_HUB else PRIVACY_PEER
        self.capabilities = TransportCapabilities(
            name=f"loopback-{endpoint_id}",
            unicast=True,
            broadcast=(mode == MODE_MESH),
            realtime=realtime,
            privacy_level=privacy,
            external_infrastructure=(mode == MODE_HUB),
        )
        wire.attach(self)

    def serve_recipient(self, recipient: str) -> None:
        self._served.add(recipient)

    def send(self, envelope: TransportEnvelope) -> SendResult:
        if self.mode == MODE_MESH:
            delivered = self._wire._fanout_mesh(self.endpoint_id, envelope)
            if delivered == 0:
                return SendResult(accepted=False, error_code="no-reachable-peer")
            return SendResult(accepted=True)
        parked = self._wire._park_on_hub(self.endpoint_id, envelope)
        if not parked:
            return SendResult(accepted=False, error_code="hub-queue-full")
        return SendResult(accepted=True)

    def poll(self, *, max_items: int = 64) -> List[TransportEnvelope]:
        items: List[TransportEnvelope] = []
        with self._wire._lock:
            while self._inbox and len(items) < max_items:
                items.append(self._inbox.popleft())
        if self.mode == MODE_HUB:
            items.extend(self._wire._claim_from_hub(self._served, max_items - len(items)))
        return items

    def pending_inbox_depth(self) -> int:
        with self._wire._lock:
            return len(self._inbox)


__all__ = [
    "MAX_WIRE_QUEUE",
    "MODE_HUB",
    "MODE_MESH",
    "LoopbackEndpoint",
    "LoopbackWire",
    "LoopbackWireError",
]
