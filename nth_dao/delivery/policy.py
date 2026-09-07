"""Route policy — how a sender chooses among available transports.

The integration design doc §8.2 rejects a fixed fallback order ("BLE → WS →
Nostr"): the router scores transports per policy. A policy is pure data and
validated fail-closed; nothing here interprets payloads or grants authority.

Two policies express the communication-mode choice the product makes
visible to users:

* centralized module  — allow only the hub/relay transport;
* decentralized federation broadcast — allow only mesh/peer transports;
* mixed               — allow both; the router scores and falls back.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from nth_dao.delivery.envelope import MAX_HOP_LIMIT
from nth_dao.delivery.transports.base import (
    PRIVACY_LOCAL,
    PRIVACY_PEER,
    PRIVACY_PUBLIC_RELAY,
)

TRANSPORT_NAME_MAX = 64


class RoutePolicyError(ValueError):
    """Raised when a policy is malformed (fail closed)."""


def _validated_names(value: Tuple[str, ...]) -> Tuple[str, ...]:
    if not isinstance(value, tuple):
        raise RoutePolicyError("allowed_transports must be a tuple of names")
    for name in value:
        if not isinstance(name, str) or not name or len(name) > TRANSPORT_NAME_MAX:
            raise RoutePolicyError("transport names must be 1..64 chars")
    if len(set(value)) != len(value):
        raise RoutePolicyError("allowed_transports must not contain duplicates")
    return value


@dataclass(frozen=True)
class RoutePolicy:
    """Pure routing policy. All fields validated on construction."""

    allowed_transports: Tuple[str, ...] = ()
    copy_count: int = 1
    require_ack: bool = True
    privacy_floor: int = PRIVACY_PUBLIC_RELAY
    prefer_realtime: bool = True
    allow_fallback: bool = True
    max_hop_limit: int = 0
    require_external_infrastructure: bool | None = None

    def __post_init__(self) -> None:
        _validated_names(self.allowed_transports)
        if isinstance(self.copy_count, bool) or not isinstance(self.copy_count, int) or self.copy_count < 1:
            raise RoutePolicyError("copy_count must be a positive integer")
        for name, value in (
            ("require_ack", self.require_ack),
            ("prefer_realtime", self.prefer_realtime),
            ("allow_fallback", self.allow_fallback),
        ):
            if not isinstance(value, bool):
                raise RoutePolicyError(f"{name} must be a boolean")
        if self.privacy_floor not in (PRIVACY_PUBLIC_RELAY, PRIVACY_PEER, PRIVACY_LOCAL):
            raise RoutePolicyError("privacy_floor must be 0, 1, or 2")
        if (
            isinstance(self.max_hop_limit, bool)
            or not isinstance(self.max_hop_limit, int)
            or not 0 <= self.max_hop_limit <= MAX_HOP_LIMIT
        ):
            raise RoutePolicyError(
                f"max_hop_limit must be an integer within [0, {MAX_HOP_LIMIT}]"
            )
        if self.require_external_infrastructure is not None and not isinstance(
            self.require_external_infrastructure, bool
        ):
            raise RoutePolicyError(
                "require_external_infrastructure must be boolean or null"
            )


CENTRALIZED_POLICY = RoutePolicy(
    allowed_transports=(),
    privacy_floor=PRIVACY_PUBLIC_RELAY,
    prefer_realtime=True,
    require_external_infrastructure=True,
)

DECENTRALIZED_POLICY = RoutePolicy(
    privacy_floor=PRIVACY_PEER,
    prefer_realtime=False,
    require_external_infrastructure=False,
)

OFFLINE_POLICY = RoutePolicy(
    privacy_floor=PRIVACY_LOCAL,
    prefer_realtime=False,
    require_ack=False,
    require_external_infrastructure=False,
)


__all__ = [
    "CENTRALIZED_POLICY",
    "DECENTRALIZED_POLICY",
    "OFFLINE_POLICY",
    "TRANSPORT_NAME_MAX",
    "RoutePolicy",
    "RoutePolicyError",
]
