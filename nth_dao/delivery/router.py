"""DeliveryRouter — policy-scored transport selection (design doc §8.2).

The router never decides whether an event is trustworthy; it only picks a
route. For one envelope it:

1. filters registered transports by policy (allowlist, privacy floor,
   payload fit, cooldown, reachability);
2. scores the survivors (realtime preference, privacy, infrastructure-free,
   health) deterministically — ties keep registration order;
3. sends to the top ``policy.copy_count`` transports, and — when
   ``allow_fallback`` is set — keeps trying the remaining candidates in
   score order until at least one accepts;
4. tracks rolling health so repeatedly failing transports cool down instead
   of eating every attempt.

Duplicate suppression across transports is the outbox's job: the first
valid signed ACK cancels the other copies. The router is stateless beyond
health counters.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    TransportEnvelope,
    TransportEnvelopeRejected,
    validate_envelope,
)
from nth_dao.delivery.policy import RoutePolicy
from nth_dao.delivery.transports.base import (
    DEFAULT_COOLDOWN_MS,
    DEFAULT_FAILURE_THRESHOLD,
    Transport,
    TRANSPORT_ACK_HOST,
    TransportHealth,
    monotonic_ms,
)

logger = logging.getLogger("nth_dao.delivery")

RouterClock = Callable[[], int]


@dataclass
class RouteAttempt:
    transport: str
    accepted: bool
    error_code: str = ""


@dataclass
class RoutingResult:
    """Outcome of one routed send."""

    attempts: List[RouteAttempt] = field(default_factory=list)
    sent_via: List[str] = field(default_factory=list)
    exhausted: bool = True

    @property
    def accepted(self) -> bool:
        return bool(self.sent_via)


@dataclass
class ReceivedEnvelope:
    transport: str
    envelope: TransportEnvelope


class DeliveryRouter:
    """Score-based router over registered transports."""

    def __init__(
        self,
        *,
        clock: Optional[RouterClock] = None,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        cooldown_ms: int = DEFAULT_COOLDOWN_MS,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be a positive integer")
        if cooldown_ms < 0:
            raise ValueError("cooldown_ms must be non-negative")
        self._clock = clock or monotonic_ms
        self._failure_threshold = failure_threshold
        self._cooldown_ms = cooldown_ms
        self._transports: Dict[str, Transport] = {}
        self._health: Dict[str, TransportHealth] = {}
        self._order: List[str] = []
        self._lock = threading.RLock()

    # ─────────────────────── registry ───────────────────────

    def register(self, transport: Transport) -> None:
        capabilities = transport.capabilities
        with self._lock:
            if capabilities.name in self._transports:
                raise ValueError(f"transport already registered: {capabilities.name}")
            self._transports[capabilities.name] = transport
            self._health[capabilities.name] = TransportHealth()
            self._order.append(capabilities.name)

    def unregister(self, name: str) -> None:
        with self._lock:
            self._transports.pop(name, None)
            self._health.pop(name, None)
            if name in self._order:
                self._order.remove(name)

    def transport_names(self) -> List[str]:
        with self._lock:
            return list(self._order)

    def health_of(self, name: str) -> Optional[TransportHealth]:
        with self._lock:
            health = self._health.get(name)
            if health is None:
                return None
            return TransportHealth(
                reachable=health.reachable,
                consecutive_failures=health.consecutive_failures,
                last_success_ms=health.last_success_ms,
                last_failure_ms=health.last_failure_ms,
            )

    # ─────────────────────── routing ───────────────────────

    def send(self, envelope: TransportEnvelope, policy: Optional[RoutePolicy] = None) -> RoutingResult:
        policy = policy or RoutePolicy()
        if not isinstance(policy, RoutePolicy):
            raise TypeError("policy must be a RoutePolicy")
        ok, reason = validate_envelope(envelope, require_signature=True)
        if not ok:
            raise TransportEnvelopeRejected(reason)
        if envelope.routing["hop_limit"] > policy.max_hop_limit:
            raise TransportEnvelopeRejected(
                "envelope hop_limit exceeds the active route policy"
            )
        candidates = self._score(envelope, policy)
        result = RoutingResult()
        now = self._clock()
        primary = candidates[: policy.copy_count]
        fallback = candidates[policy.copy_count:] if policy.allow_fallback else []

        for name in primary:
            outcome = self._dispatch(name, envelope, now)
            result.attempts.append(outcome)
            if outcome.accepted:
                result.sent_via.append(name)

        if not result.accepted and policy.allow_fallback:
            for name in fallback:
                outcome = self._dispatch(name, envelope, now)
                result.attempts.append(outcome)
                if outcome.accepted:
                    result.sent_via.append(name)
                    break

        result.exhausted = not result.accepted
        return result

    def receive(self, *, max_items: int = 64) -> List[ReceivedEnvelope]:
        """Poll every registered transport and drain what arrived."""

        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
            raise ValueError("max_items must be a positive integer")
        received: List[ReceivedEnvelope] = []
        with self._lock:
            names = list(self._order)
            transports = dict(self._transports)
        for name in names:
            remaining = max_items - len(received)
            if remaining <= 0:
                break
            transport = transports[name]
            try:
                items = transport.poll(max_items=remaining)
            except Exception as exc:
                logger.warning("transport %s poll failed: %s", name, exc)
                self._note_failure(name, self._clock())
                continue
            for envelope in items[:remaining]:
                received.append(ReceivedEnvelope(transport=name, envelope=envelope))
        return received

    def stats(self) -> Dict[str, Dict[str, object]]:
        now = self._clock()
        with self._lock:
            snapshot: Dict[str, Dict[str, object]] = {}
            for name in self._order:
                health = self._health[name]
                snapshot[name] = {
                    "reachable": health.reachable,
                    "consecutive_failures": health.consecutive_failures,
                    "in_cooldown": health.in_cooldown(
                        now,
                        threshold=self._failure_threshold,
                        cooldown_ms=self._cooldown_ms,
                    ),
                }
            return snapshot

    # ─────────────────────── internals ───────────────────────

    def _score(
        self, envelope: TransportEnvelope, policy: RoutePolicy
    ) -> List[str]:
        envelope_bytes = len(canonical_json(envelope.to_dict()))
        scored: List[tuple[int, int, str]] = []
        now = self._clock()
        with self._lock:
            for index, name in enumerate(self._order):
                transport = self._transports[name]
                capabilities = transport.capabilities
                if policy.allowed_transports and name not in policy.allowed_transports:
                    continue
                if envelope.recipient.startswith("did:key:") and not capabilities.unicast:
                    continue
                if capabilities.privacy_level < policy.privacy_floor:
                    continue
                if policy.require_ack and capabilities.ack_mode != TRANSPORT_ACK_HOST:
                    continue
                infrastructure = policy.require_external_infrastructure
                if (
                    infrastructure is not None
                    and capabilities.external_infrastructure != infrastructure
                ):
                    continue
                if envelope_bytes > capabilities.max_envelope_bytes:
                    continue
                health = self._health[name]
                if not health.reachable:
                    continue
                if health.in_cooldown(
                    now,
                    threshold=self._failure_threshold,
                    cooldown_ms=self._cooldown_ms,
                ):
                    continue
                score = 0
                if capabilities.realtime == policy.prefer_realtime:
                    score += 4
                score += capabilities.privacy_level
                if not capabilities.external_infrastructure:
                    score += 2
                if health.consecutive_failures == 0:
                    score += 1
                scored.append((-score, index, name))
        scored.sort()
        return [name for _, _, name in scored]

    def _dispatch(self, name: str, envelope: TransportEnvelope, now: int) -> RouteAttempt:
        with self._lock:
            transport = self._transports.get(name)
        if transport is None:  # pragma: no cover - raced with unregister
            return RouteAttempt(transport=name, accepted=False, error_code="unregistered")
        try:
            outcome = transport.send(envelope)
        except Exception as exc:
            logger.warning("transport %s send failed: %s", name, exc)
            self._note_failure(name, now)
            return RouteAttempt(transport=name, accepted=False, error_code="transport-error")
        if outcome.accepted:
            self._note_success(name, now)
        else:
            self._note_failure(name, now)
        return RouteAttempt(
            transport=name, accepted=outcome.accepted, error_code=outcome.error_code
        )

    def _note_success(self, name: str, now_ms: int) -> None:
        with self._lock:
            health = self._health.get(name)
            if health is None:
                return
            health.consecutive_failures = 0
            health.last_success_ms = now_ms
            health.reachable = True

    def _note_failure(self, name: str, now_ms: int) -> None:
        with self._lock:
            health = self._health.get(name)
            if health is None:
                return
            health.consecutive_failures += 1
            health.last_failure_ms = now_ms


__all__ = [
    "DeliveryRouter",
    "ReceivedEnvelope",
    "RouteAttempt",
    "RoutePolicy",
    "RoutingResult",
]
