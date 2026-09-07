"""Nostr transport — public relay tier for the delivery router (Phase 2 N3).

Borrowing rule: the event construction, signature, and relay wire protocol
are entirely nostr-sdk's (N1 + N2). This module is the delivery-layer
Transport adapter: wraps a ``NostrRelayClient`` and the envelope↔event
mapping behind the standard ``Transport`` interface.

Security boundary (design doc §8.3): the Nostr relay tier is world-readable
broadcast infrastructure. Only envelopes with broadcast recipients
(dao:/channel:) are accepted — private (did:key) envelopes are refused at
send time by the N1 core's public-tier policy. The privacy level is
declared ``PRIVACY_PUBLIC_RELAY`` so the router's privacy floors exclude
this transport for sensitive traffic automatically.
"""

from __future__ import annotations

import logging
import time
from typing import List, Optional

from nth_dao.delivery.envelope import TransportEnvelope
from nth_dao.delivery.transports.base import (
    PRIVACY_PUBLIC_RELAY,
    SendResult,
    Transport,
    TransportCapabilities,
    TransportHealth,
)
from nth_dao.nostr import (
    NOSTR_EVENT_KIND,
    NOSTR_NAMESPACE,
    NostrKeyBinding,
    NostrKeys,
    NostrRelayClient,
    envelope_event,
    envelope_from_event,
    verify_key_binding_standalone,
)

logger = logging.getLogger("nth_dao.nostr")

NOSTR_SUBSCRIBE_KINDS = [NOSTR_EVENT_KIND]


class NostrTransport(Transport):
    """Delivery Transport over the public Nostr relay tier."""

    def __init__(
        self,
        identity_keys: NostrKeys,
        *,
        relay_urls: List[str],
        name: str = "nostr",
        publish_timeout: float = 10.0,
        binding: NostrKeyBinding,
        trusted_bindings: Optional[List[NostrKeyBinding]] = None,
    ) -> None:
        if not isinstance(binding, NostrKeyBinding):
            raise ValueError("binding must be a signed NostrKeyBinding")
        if trusted_bindings is not None and not isinstance(trusted_bindings, list):
            raise ValueError("trusted_bindings must be a list")
        now_ms = int(time.time() * 1000)
        verified = [binding, *(trusted_bindings or [])]
        by_did: dict[str, NostrKeyBinding] = {}
        for candidate in verified:
            if not isinstance(candidate, NostrKeyBinding):
                raise ValueError("trusted_bindings must contain NostrKeyBinding values")
            ok, reason = verify_key_binding_standalone(candidate, now_ms=now_ms)
            if not ok:
                raise ValueError(f"invalid Nostr key binding: {reason}")
            current = by_did.get(candidate.nth_did)
            if current is not None and current.created_at_ms == candidate.created_at_ms:
                if current.nostr_pubkey != candidate.nostr_pubkey:
                    raise ValueError("conflicting Nostr bindings have the same timestamp")
                continue
            if current is None or candidate.created_at_ms > current.created_at_ms:
                by_did[candidate.nth_did] = candidate
        if binding.nostr_pubkey != identity_keys.public_key_hex:
            raise ValueError("binding does not name the transport publishing key")
        if by_did.get(binding.nth_did) != binding:
            raise ValueError("the publishing binding is superseded by a newer binding")
        by_pubkey: dict[str, NostrKeyBinding] = {}
        for candidate in by_did.values():
            existing_binding = by_pubkey.get(candidate.nostr_pubkey)
            if existing_binding is not None and existing_binding.nth_did != candidate.nth_did:
                raise ValueError("one Nostr key is bound to multiple NTH identities")
            by_pubkey[candidate.nostr_pubkey] = candidate
        self._relay_client = NostrRelayClient(
            identity_keys,
            relay_urls=relay_urls,
            name=name,
            publish_timeout=publish_timeout,
        )
        self._keys = identity_keys
        self._binding = binding
        self._trusted_bindings_by_pubkey = by_pubkey
        self.capabilities = TransportCapabilities(
            name=name,
            unicast=False,
            broadcast=True,
            realtime=True,
            privacy_level=PRIVACY_PUBLIC_RELAY,
            external_infrastructure=True,
            ack_mode="host",
        )

    def start(self) -> None:
        self._relay_client.start()
        try:
            self._relay_client.subscribe_events(
                kinds=NOSTR_SUBSCRIBE_KINDS,
                authors=sorted(self._trusted_bindings_by_pubkey),
                namespace=NOSTR_NAMESPACE,
            )
        except Exception as exc:  # noqa: BLE001 - operability: publish-only
            logger.warning(
                "nostr subscription setup failed; transport continues in "
                "publish-only mode (poll returns empty): %s", exc
            )

    def stop(self) -> None:
        self._relay_client.stop()

    def send(self, envelope: TransportEnvelope) -> SendResult:
        try:
            event = envelope_event(
                envelope, self._keys, created_at_seconds=int(_time()),
                binding=self._binding,
            )
        except Exception as exc:  # noqa: BLE001 - policy/crypto rejections
            logger.warning("nostr send rejected: %s", exc)
            return SendResult(accepted=False, error_code=str(exc)[:200])
        if self._relay_client.publish(event):
            return SendResult(accepted=True)
        return SendResult(accepted=False, error_code="nostr-relay-unreachable")

    def poll(self, *, max_items: int = 64) -> List[TransportEnvelope]:
        """Drain subscribed Nostr events, re-validating each envelope."""

        envelopes: List[TransportEnvelope] = []
        for event in self._relay_client.poll_events(max_items=max_items):
            try:
                author_pubkey = event.author().to_hex()
                trusted_binding = self._trusted_bindings_by_pubkey.get(author_pubkey)
                if trusted_binding is None:
                    raise ValueError("Nostr event author is not in the binding allowlist")
                binding_ok, binding_reason = verify_key_binding_standalone(
                    trusted_binding, now_ms=int(time.time() * 1000)
                )
                if not binding_ok:
                    raise ValueError(f"Nostr event author binding expired: {binding_reason}")
                envelope = envelope_from_event(event)
                if envelope.sender_did != trusted_binding.nth_did:
                    raise ValueError("Nostr event author binding does not match envelope sender")
                envelopes.append(envelope)
            except Exception:  # noqa: BLE001 - hostile events fail closed
                logger.debug("nostr event failed envelope validation; dropping")
                continue
        return envelopes

    def health(self) -> TransportHealth:
        return TransportHealth(reachable=self._relay_client.is_running)


def _time() -> float:
    return time.time()


__all__ = ["NOSTR_SUBSCRIBE_KINDS", "NostrTransport"]
