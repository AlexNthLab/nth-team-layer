"""Nostr adapter core (Phase 2) — internet relay tier for the delivery layer.

Design doc §8.3 / §6.3: Nostr carries *public, low-sensitivity* traffic —
delivery-envelope broadcast, Agent Cards, task/listing discovery. It never
grants NTH authority and never handles private envelope payloads.

Borrowing rule: ALL Nostr wire machinery (secp256k1 BIP340 signing, NIP-01
event serialization, relay JSON protocol, reconnection, OK handling) is
delegated to the maintained `nostr-sdk` binding (optional extra
``nth-dao[nostr]``, pinned ``>=0.45,<0.46`` — pre-1.0 upstream churn
protection). This package adds only the NTH-specific mapping:

OPERABILITY/SECURITY WARNING: content published through relays is WORLD-
READABLE and IMMUTABLE — even with a NIP-40 expiration tag, not all relays
honor deletion. Once published, assume the envelope content is permanently
accessible. Only public-tier envelopes (broadcast discovery, public
channels) may ride this tier; private payloads (single-recipient DMs,
payment data) must never be wrapped here. The N3 transport adapter
enforces a public-tier policy and its allowlist is fed exclusively by
VERIFIED NostrKeyBinding documents (latest-wins per NTH did) — an
unverified npub is never accepted as a NTH member's relay identity.

* :class:`NostrKeys` — thin wrapper over ``nostr_sdk.Keys`` (deterministic
  parse, x-only public key hex).
* :class:`NostrKeyBinding` — a NTH Ed25519 identity signs a binding document
  asserting ownership of a Nostr key (§6.3: the two key families cannot be
  converted; the binding is signed evidence, revocable by re-issuance).
* :func:`envelope_event` / :func:`envelope_from_event` — a delivery envelope
  travels as the content of a kind-30078 (NIP-78 app-data) event whose
  ``d`` tag pins the envelope message_id. The event signature is verified
  by nostr-sdk and the envelope is re-validated fail-closed on receipt.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
    TransportEnvelopeRejected,
    validate_envelope,
)

try:  # pragma: no cover - exercised via importorskip in tests
    import nostr_sdk as _nostr_sdk  # type: ignore[import-untyped]
    from nostr_sdk import Event as _Event
    from nostr_sdk import EventBuilder as _EventBuilder
    from nostr_sdk import Keys as _Keys
    from nostr_sdk import Kind as _Kind
    from nostr_sdk import Tag as _Tag
    _NOSTR_AVAILABLE = True
except ImportError:  # pragma: no cover
    _nostr_sdk = None
    _Event = None
    _EventBuilder = None
    _Keys = None
    _Kind = None
    _Tag = None
    _NOSTR_AVAILABLE = False

NOSTR_EVENT_KIND = 30078          # NIP-78 parameterized app-data event
NOSTR_NAMESPACE = "nth-dao-delivery-v1"
BINDING_KIND = "nth-nostr-key-binding-v1"
BINDING_MAX_AGE_MS = 365 * 24 * 60 * 60 * 1000  # one year
_ENVELOPE_EVENT_D_TAG = "d"


class NostrAdapterUnavailable(RuntimeError):
    """Raised when the ``nostr`` extra is not installed."""


logger = logging.getLogger("nth_dao.nostr")


def _require_nostr() -> None:
    if not _NOSTR_AVAILABLE:
        raise NostrAdapterUnavailable(
            "nostr support requires the optional extra: pip install nth-dao[nostr]"
        )


class NostrKeys:
    """Thin wrapper over ``nostr_sdk.Keys`` (secp256k1, BIP340)."""

    def __init__(self, keys: Any) -> None:
        _require_nostr()
        self._keys = keys

    @classmethod
    def generate(cls) -> "NostrKeys":
        _require_nostr()
        return cls(_Keys.generate())

    @classmethod
    def parse(cls, secret_key_hex: str) -> "NostrKeys":
        """Import a secret key from 64-char hex (deterministic tests, import)."""

        _require_nostr()
        if not isinstance(secret_key_hex, str):
            raise ValueError("secret key must be hex text")
        try:
            return cls(_Keys.parse(secret_key_hex))
        except Exception as exc:  # noqa: BLE001 - rust errors are opaque
            raise ValueError(f"invalid nostr secret key: {exc}") from exc

    @property
    def public_key_hex(self) -> str:
        """64-char x-only BIP340 public key (the Nostr npub body)."""

        return self._keys.public_key().to_hex()

    @property
    def raw(self) -> Any:
        return self._keys


@dataclass(frozen=True)
class NostrKeyBinding:
    """A NTH Ed25519 identity signing ownership of one Nostr key (§6.3)."""

    nth_did: str
    nostr_pubkey: str
    created_at_ms: int
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": BINDING_KIND,
            "nth_did": self.nth_did,
            "nostr_pubkey": self.nostr_pubkey,
            "created_at_ms": self.created_at_ms,
            "signature": self.signature,
        }

    def signing_body(self) -> Dict[str, Any]:
        return {
            key: value for key, value in self.to_dict().items() if key != "signature"
        }


def _check_binding_shape(binding: NostrKeyBinding, *, now_ms: int) -> str:
    if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms <= 0:
        return "now_ms must be a positive integer"
    if (
        not isinstance(binding.nth_did, str)
        or binding.nth_did != binding.nth_did.strip()
        or not binding.nth_did.startswith("did:key:")
    ):
        return "nth_did must be a did:key DID"
    if (
        not isinstance(binding.nostr_pubkey, str)
        or len(binding.nostr_pubkey) != 64
        or any(character not in "0123456789abcdef" for character in binding.nostr_pubkey)
    ):
        return "nostr_pubkey must be 64-char lowercase x-only hex"
    if isinstance(binding.created_at_ms, bool) or not isinstance(binding.created_at_ms, int):
        return "created_at_ms must be an integer"
    if binding.created_at_ms <= 0 or binding.created_at_ms > now_ms:
        return "created_at_ms must be in the past"
    if now_ms - binding.created_at_ms > BINDING_MAX_AGE_MS:
        return "binding older than one year must be re-issued"
    return "ok"


def sign_key_binding(
    identity: Any,
    *,
    nostr_keys: NostrKeys,
    created_at_ms: int,
) -> NostrKeyBinding:
    """Bind a Nostr key to a NTH Ed25519 identity (signature by the identity)."""

    binding = NostrKeyBinding(
        nth_did=identity.as_did(),
        nostr_pubkey=nostr_keys.public_key_hex,
        created_at_ms=created_at_ms,
    )
    reason = _check_binding_shape(binding, now_ms=created_at_ms)
    if reason != "ok":
        raise ValueError(f"invalid key binding: {reason}")
    return NostrKeyBinding(
        nth_did=binding.nth_did,
        nostr_pubkey=binding.nostr_pubkey,
        created_at_ms=binding.created_at_ms,
        signature=identity.sign_json(binding.signing_body()),
    )


def verify_key_binding_standalone(
    binding: NostrKeyBinding,
    *,
    now_ms: int,
) -> tuple[bool, str]:
    """Verify a binding using only the DID embedded in it (publish-side gate).

    The binding's Ed25519 signature is checked against the pubkey decoded
    from ``binding.nth_did`` — no identity object required, which is exactly
    what a publishing process has."""

    from nth_dao.did_key import DIDKeyError, decode_ed25519_did_key_hex
    from nth_dao.identity import AgentID, AgentIdentity

    reason = _check_binding_shape(binding, now_ms=now_ms)
    if reason != "ok":
        return False, reason
    if (
        not isinstance(binding.signature, str)
        or len(binding.signature) != 128
        or any(character not in "0123456789abcdef" for character in binding.signature)
    ):
        return False, "binding signature must be 128-char lowercase hex"
    try:
        pubkey_hex = decode_ed25519_did_key_hex(binding.nth_did) or ""
    except (DIDKeyError, TypeError, ValueError) as exc:
        return False, f"binding nth_did is invalid: {exc}"
    if len(pubkey_hex) != 64:
        return False, "binding nth_did is not an Ed25519 did:key"
    agent_id = AgentID.from_pubkey(pubkey_hex)
    probe = AgentIdentity(
        agent_id=agent_id,
        _signing_key=None,
        _verify_key=bytes.fromhex(pubkey_hex),
    )
    if not probe.verify_json(binding.signing_body(), binding.signature, pubkey_hex):
        return False, "binding signature verification failed"
    return True, "ok"


def verify_key_binding(
    binding: NostrKeyBinding,
    *,
    identity: Any,
    now_ms: int,
) -> tuple[bool, str]:
    """Verify one binding against the claimed NTH identity (fail closed)."""

    reason = _check_binding_shape(binding, now_ms=now_ms)
    if reason != "ok":
        return False, reason
    if binding.nth_did != identity.as_did():
        return False, "binding nth_did does not match the verifying identity"
    if not identity.verify_json(
        binding.signing_body(), binding.signature, identity.pubkey_hex
    ):
        return False, "binding signature verification failed"
    return True, "ok"


def envelope_event(
    envelope: TransportEnvelope,
    nostr_keys: NostrKeys,
    *,
    created_at_seconds: int,
    binding: "NostrKeyBinding | None" = None,
) -> Any:
    """Wrap one signed envelope as a kind-30078 Nostr event (content = canonical
    envelope JSON, ``d`` tag = message_id). The envelope must already carry its
    author signature; the Nostr event adds the relay-tier signature on top.

    Public-tier policy (round-15 bugs CC-b/CC-c):

    * only broadcast recipients (``dao:``/``channel:``) are accepted — a
      single-recipient ``did:key:`` envelope is private traffic and is
      refused here rather than published world-readable;
    * when ``binding`` is provided it must (a) carry a valid signature from
      its own claimed NTH did, (b) name exactly this ``nostr_keys`` public
      key, and (c) belong to the envelope sender — otherwise the event would
      be published under a relay key that no verified allowlist delivers."""

    _require_nostr()
    ok, reason = validate_envelope(envelope, require_signature=True)
    if not ok:
        raise TransportEnvelopeRejected(reason)
    if envelope.recipient.startswith("did:key:"):
        raise TransportEnvelopeRejected(
            "public relay tier carries broadcast traffic only: did:key "
            "recipients are private and must use a private transport"
        )
    if binding is not None:
        b_ok, b_reason = verify_key_binding_standalone(
            binding, now_ms=int(time.time() * 1000)
        )
        if not b_ok:
            raise TransportEnvelopeRejected(f"nostr key binding invalid: {b_reason}")
        if binding.nostr_pubkey != nostr_keys.public_key_hex:
            raise TransportEnvelopeRejected(
                "nostr key binding does not name the publishing key"
            )
        if binding.nth_did != envelope.sender_did:
            raise TransportEnvelopeRejected(
                "nostr key binding belongs to a different NTH identity than "
                "the envelope sender"
            )
    # NIP-01 requires an integer seconds timestamp; floats, negatives, and
    # far-future values would poison the wire (round-12 bug BB-r)
    if (
        isinstance(created_at_seconds, bool)
        or not isinstance(created_at_seconds, int)
        or created_at_seconds <= 0
        or created_at_seconds > int(time.time()) + 3600
    ):
        raise TransportEnvelopeRejected(
            "created_at_seconds must be a positive integer within one hour "
            "of the future"
        )
    content = canonical_json(envelope.to_dict()).decode("utf-8")
    # the validated created_at_seconds is actually applied (round-13 bug BB-t:
    # it used to be validated then silently dropped, making deterministic
    # replay impossible — same envelope+keys produced fresh ids every run)
    from nostr_sdk import Timestamp as _Timestamp

    # NIP-40 expiration tag: tells relays to delete the event after the
    # envelope's own TTL — without it, expired envelopes remain world-
    # readable on relays indefinitely (round-17 bug BB-w2)
    expiration_tag = _Tag.parse([
        "expiration",
        str(envelope.expires_at_ms // 1000),
    ])
    return (
        _EventBuilder(_Kind(NOSTR_EVENT_KIND), content)
        .tags([
            _Tag.parse([_ENVELOPE_EVENT_D_TAG, envelope.message_id]),
            _Tag.parse(["t", NOSTR_NAMESPACE]),
            expiration_tag,
        ])
        .custom_created_at(_Timestamp.from_secs(created_at_seconds))
        .finalize(nostr_keys.raw)
    )


def envelope_from_event(event: Any) -> TransportEnvelope:
    """Verify one Nostr event and extract its delivery envelope (fail closed).

    Two independent checks: the Nostr event signature (relay-tier, via
    nostr-sdk) and the envelope's own author signature (delivery-tier, via
    ``validate_envelope``). A relay cannot forge either; a hostile author
    cannot skip both.
    """

    _require_nostr()
    if not event.verify_signature():
        raise TransportEnvelopeRejected("nostr event signature verification failed")
    if event.kind().as_u16() != NOSTR_EVENT_KIND:
        raise TransportEnvelopeRejected("wrong nostr event kind")
    if NOSTR_NAMESPACE not in _extract_tag_values(event, "t"):
        raise TransportEnvelopeRejected("nostr event is outside the NTH namespace")
    # the d tag is the parameterized-replaceable addressing key: an event
    # whose d tag does not name the carried envelope's message_id is either
    # misrouted or a hostile slot-collision (round-12 bug BB-q)
    content = event.content()
    if not isinstance(content, str) or not content:
        raise TransportEnvelopeRejected("nostr event content is empty")
    if len(content.encode("utf-8")) > MAX_ENVELOPE_BYTES:
        raise TransportEnvelopeRejected("nostr event content exceeds the envelope limit")
    try:
        parsed = json.loads(content)
        envelope = TransportEnvelope.from_dict(parsed)
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise TransportEnvelopeRejected(f"content is not an envelope: {exc}") from exc
    if canonical_json(envelope.to_dict()).decode("utf-8") != content:
        raise TransportEnvelopeRejected("nostr envelope content is not canonical JSON")
    ok, reason = validate_envelope(envelope, require_signature=True)
    if not ok:
        logger.warning("rejecting nostr envelope event: %s", reason)
        raise TransportEnvelopeRejected(f"envelope invalid: {reason}")
    expected_d = _extract_d_tag(event)
    if expected_d != envelope.message_id:
        raise TransportEnvelopeRejected(
            "event d tag does not address the carried envelope message_id"
        )
    return envelope


def _extract_d_tag(event: Any) -> "str | None":
    """Return the event's first ``d`` tag value, or None when absent."""

    try:
        for tag in event.tags():
            tags_list = tag.to_vec()
            if len(tags_list) >= 2 and tags_list[0] == _ENVELOPE_EVENT_D_TAG:
                return tags_list[1]
    except Exception:  # noqa: BLE001 - malformed tags fail closed at the caller
        return None
    return None


def _extract_tag_values(event: Any, name: str) -> list[str]:
    values: list[str] = []
    try:
        for tag in event.tags():
            tag_items = tag.to_vec()
            if len(tag_items) >= 2 and tag_items[0] == name:
                values.append(tag_items[1])
    except Exception:  # noqa: BLE001 - malformed tags fail closed at the caller
        return []
    return values


__all__ = [
    "BINDING_KIND",
    "BINDING_MAX_AGE_MS",
    "NOSTR_EVENT_KIND",
    "NOSTR_NAMESPACE",
    "NostrAdapterUnavailable",
    "NostrKeyBinding",
    "NostrKeys",
    "envelope_event",
    "envelope_from_event",
    "sign_key_binding",
    "verify_key_binding",
    "verify_key_binding_standalone",
]

from nth_dao.nostr.relay_client import (  # noqa: E402 - re-export
    NostrRelayClient,
    NostrRelayError,
)

__all__ += ["NostrRelayClient", "NostrRelayError"]
