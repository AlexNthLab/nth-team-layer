"""TransportEnvelope v1 — the transport-agnostic signed message envelope.

Every domain event (channel message, task announcement, mission update,
trade offer, mandate, ...) travels between nodes as one opaque canonical-JSON
envelope. The envelope is the ONLY thing transports see, and the ONLY thing
the inbox needs to fail-closed-validate before business logic runs.

Wire contract (v1, do not change without a protocol major bump):

* The envelope serializes to canonical JSON (``nth_dao.canonical_json``).
* ``message_id`` is content-addressed: ``sha256:`` over the canonical bytes
  of the signing body, so identity, dedup, and signature all bind the same
  bytes.
* The signing body covers every author-owned field. ``signature`` itself and
  the mutable per-hop routing counter ``routing.hop_count`` are excluded, so
  a relay can forward an envelope (hop_count + 1) without breaking the
  author signature, while the author, recipient, payload, TTL, and hop
  budget stay signature-protected.
* Unknown fields, unknown versions, floats, oversized or too-deep payloads,
  inverted TTLs, and oversized TTLs are all rejected (fail closed).

Timeouts and limits are module constants so a port can produce byte-identical
accept/reject behavior; conformance vectors pin them down in
``nth_dao/conformance/vectors.json``.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Union

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key,
    decode_ed25519_did_key_hex,
    is_did_key,
)
from nth_dao.identity import _NACL_AVAILABLE, AgentIdentity

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]

logger = logging.getLogger("nth_dao.delivery")

ENVELOPE_PROTOCOL = "nth-transport-envelope"
ENVELOPE_VERSION = 1

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_PAYLOAD_BYTES = 256 * 1024
MAX_ENVELOPE_BYTES = 512 * 1024
MAX_PAYLOAD_DEPTH = 16
MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000
MAX_CLOCK_SKEW_MS = 5 * 60 * 1000
MAX_HOP_LIMIT = 16
DEFAULT_HOP_LIMIT = 0

_KIND_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9]{16,128}$")
_LOCAL_ID_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_BASE_FIELDS = (
    "protocol",
    "version",
    "message_id",
    "kind",
    "sender_did",
    "recipient",
    "created_at_ms",
    "expires_at_ms",
    "nonce",
    "payload_hash",
    "payload",
    "routing",
    "signature",
)
_MUTABLE_ROUTING_KEYS = ("hop_count",)


class TransportEnvelopeRejected(ValueError):
    """Raised when an envelope cannot be built or fails validation."""


@dataclass
class TransportEnvelope:
    """One signed, transport-agnostic message. Plain data, zero behavior.

    ``dao_id`` is optional; when unset it is omitted from the wire dict so
    that the canonical bytes stay stable for senders that never use it.
    """

    message_id: str
    kind: str
    sender_did: str
    recipient: str
    created_at_ms: int
    expires_at_ms: int
    nonce: str
    payload_hash: str
    payload: Dict[str, Any]
    routing: Dict[str, Any]
    signature: str = ""
    protocol: str = ENVELOPE_PROTOCOL
    version: int = ENVELOPE_VERSION
    dao_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {key: value for key, value in asdict(self).items() if value is not None}
        return data

    def signing_body(self) -> Dict[str, Any]:
        """The author-signed projection: no signature, no mutable hop count.

        ``message_id`` IS included — the author signs the content address,
        binding the identity of the message into the signature.
        """

        body = {
            key: value
            for key, value in self.to_dict().items()
            if key != "signature"
        }
        routing = {
            key: value
            for key, value in body.get("routing", {}).items()
            if key not in _MUTABLE_ROUTING_KEYS
        }
        body["routing"] = routing
        return body

    def content_body(self) -> Dict[str, Any]:
        """The content-addressed projection used to derive ``message_id``.

        Excludes the signature, the message_id itself, and the mutable hop
        counter, so the address is stable across relays and identical content
        always produces the identical id.
        """

        body = self.signing_body()
        body.pop("message_id", None)
        return body

    @classmethod
    def allowed_field_sets(cls) -> tuple[frozenset[str], ...]:
        return (
            frozenset(_BASE_FIELDS) | {"dao_id"},
            frozenset(_BASE_FIELDS),
        )

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "TransportEnvelope":
        if not isinstance(value, dict):
            raise TransportEnvelopeRejected("envelope must be a JSON object")
        if frozenset(value) not in cls.allowed_field_sets():
            raise TransportEnvelopeRejected("envelope has missing or unknown fields")
        try:
            return cls(**value)
        except TypeError as exc:  # pragma: no cover - guarded by field-set check
            raise TransportEnvelopeRejected(f"malformed envelope: {exc}") from exc


def _recode_envelope(envelope: TransportEnvelope) -> Dict[str, Any]:
    """Rebuild a plain dict with dao_id omitted when unset."""

    data = envelope.to_dict()
    if data.get("dao_id") is None:
        data.pop("dao_id", None)
    return data


def _check_safe_int(value: Any, *, path: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TransportEnvelopeRejected(f"{path} must be an integer")
    if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise TransportEnvelopeRejected(f"{path} exceeds the safe integer range")


def _check_payload_shape(value: Any, *, depth: int = 0) -> None:
    """Reject floats, unsafe integers, and over-deep payloads (fail closed)."""

    if depth > MAX_PAYLOAD_DEPTH:
        raise TransportEnvelopeRejected("payload nesting exceeds the depth limit")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise TransportEnvelopeRejected("payload integer exceeds safe range")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_payload_shape(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise TransportEnvelopeRejected("payload object keys must be strings")
            _check_payload_shape(item, depth=depth + 1)
        return
    raise TransportEnvelopeRejected(f"unsupported payload value at depth {depth}")


def _payload_digest(payload: Dict[str, Any]) -> str:
    encoded = canonical_json(payload)
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _local_id(value: Any, *, what: str, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _LOCAL_ID_RE.fullmatch(value) is None
        or ".." in value
    ):
        raise TransportEnvelopeRejected(f"{what} is invalid")
    return value


def _validate_recipient(recipient: Any) -> str:
    if not isinstance(recipient, str) or not recipient or len(recipient) > 256:
        raise TransportEnvelopeRejected("recipient is invalid")
    if recipient.startswith("did:key:"):
        try:
            decode_ed25519_did_key(recipient)
        except (DIDKeyError, ValueError, TypeError) as exc:
            raise TransportEnvelopeRejected(f"recipient DID is invalid: {exc}") from exc
        return recipient
    for scheme in ("dao:", "channel:"):
        if recipient.startswith(scheme):
            local = recipient[len(scheme):]
            _local_id(local, what=f"{scheme[:-1]} recipient", maximum=200)
            return recipient
    raise TransportEnvelopeRejected(
        "recipient must be did:key:, dao:<id>, or channel:<id>"
    )


def _validate_routing(routing: Any) -> None:
    if not isinstance(routing, dict):
        raise TransportEnvelopeRejected("routing must be an object")
    allowed = {"hop_limit", "hop_count", "reply_to"}
    unknown = set(routing) - allowed
    if unknown:
        raise TransportEnvelopeRejected(f"routing has unknown fields: {sorted(unknown)}")
    if "hop_limit" not in routing or "hop_count" not in routing:
        raise TransportEnvelopeRejected("routing requires hop_limit and hop_count")
    _check_safe_int(routing["hop_limit"], path="routing.hop_limit")
    _check_safe_int(routing["hop_count"], path="routing.hop_count")
    if not 0 <= routing["hop_limit"] <= MAX_HOP_LIMIT:
        raise TransportEnvelopeRejected(f"routing.hop_limit must be 0..{MAX_HOP_LIMIT}")
    if not 0 <= routing["hop_count"] <= routing["hop_limit"]:
        raise TransportEnvelopeRejected("routing.hop_count must be 0..hop_limit")
    reply_to = routing.get("reply_to")
    if "reply_to" in routing:
        # explicit null is refused for wire strictness: absent and null must
        # not produce two different content addresses for one semantic value
        if not isinstance(reply_to, str) or not reply_to:
            raise TransportEnvelopeRejected("routing.reply_to must be a non-empty string")
        try:
            _validate_recipient(reply_to)
        except TransportEnvelopeRejected as exc:
            raise TransportEnvelopeRejected(f"routing.reply_to is invalid: {exc}") from exc


def _validate_envelope(
    envelope: TransportEnvelope,
    *,
    now_ms: Optional[int] = None,
    require_signature: bool = True,
) -> tuple[bool, str]:
    """Full fail-closed validation. Returns (ok, reason) like CommerceEnvelope."""

    if not isinstance(envelope, TransportEnvelope):
        return False, "envelope must be a TransportEnvelope"
    if envelope.protocol != ENVELOPE_PROTOCOL:
        return False, "wrong envelope protocol"
    if (
        isinstance(envelope.version, bool)
        or not isinstance(envelope.version, int)
        or envelope.version != ENVELOPE_VERSION
    ):
        return False, "unsupported envelope version"

    wire = _recode_envelope(envelope)
    if frozenset(wire) not in TransportEnvelope.allowed_field_sets():
        return False, "envelope has missing or unknown fields"

    if not isinstance(envelope.kind, str) or _KIND_RE.fullmatch(envelope.kind) is None or ".." in envelope.kind:
        return False, "envelope kind is invalid"

    if not is_did_key(envelope.sender_did):
        return False, "invalid sender DID"
    try:
        decode_ed25519_did_key(envelope.sender_did)
    except (DIDKeyError, ValueError, TypeError) as exc:
        return False, f"sender DID is not a decodable Ed25519 did:key: {exc}"

    try:
        _validate_recipient(envelope.recipient)
    except TransportEnvelopeRejected as exc:
        return False, str(exc)

    if envelope.dao_id is not None:
        try:
            _local_id(envelope.dao_id, what="dao_id")
        except TransportEnvelopeRejected as exc:
            return False, str(exc)

    try:
        _check_safe_int(envelope.created_at_ms, path="created_at_ms")
    except TransportEnvelopeRejected as exc:
        return False, str(exc)
    if envelope.created_at_ms <= 0:
        return False, "created_at_ms must be positive"
    try:
        _check_safe_int(envelope.expires_at_ms, path="expires_at_ms")
    except TransportEnvelopeRejected as exc:
        return False, str(exc)
    if envelope.expires_at_ms <= envelope.created_at_ms:
        return False, "expires_at_ms must be after created_at_ms"
    if envelope.expires_at_ms - envelope.created_at_ms > MAX_TTL_MS:
        return False, "envelope TTL exceeds the maximum"
    if now_ms is not None:
        if not isinstance(now_ms, int) or isinstance(now_ms, bool):
            return False, "now_ms must be an integer"
        if not -MAX_SAFE_INTEGER <= now_ms <= MAX_SAFE_INTEGER:
            return False, "now_ms exceeds the safe integer range"
        if envelope.created_at_ms > now_ms + MAX_CLOCK_SKEW_MS:
            return False, "envelope created in the future beyond clock skew"
        if envelope.expires_at_ms <= now_ms:
            return False, "envelope expired"

    if not isinstance(envelope.nonce, str) or _NONCE_RE.fullmatch(envelope.nonce) is None:
        return False, "nonce must be 16..128 alphanumeric characters"

    if not isinstance(envelope.payload, dict):
        return False, "payload must be an object"
    try:
        _check_payload_shape(envelope.payload)
        encoded_payload = canonical_json(envelope.payload)
    except TransportEnvelopeRejected as exc:
        return False, str(exc)
    except (TypeError, ValueError, RecursionError) as exc:
        return False, f"payload is not canonical JSON: {exc}"
    if len(encoded_payload) > MAX_PAYLOAD_BYTES:
        return False, "envelope payload too large"
    if envelope.payload_hash != _payload_digest(envelope.payload):
        return False, "payload hash does not match payload"

    try:
        _validate_routing(envelope.routing)
    except TransportEnvelopeRejected as exc:
        return False, str(exc)

    try:
        expected_id = _content_address(envelope)
    except (TypeError, ValueError, RecursionError) as exc:
        return False, f"content body is not canonical JSON: {exc}"
    if envelope.message_id != expected_id:
        return False, "message id does not match envelope content"

    try:
        wire_encoded = canonical_json(wire)
    except (TypeError, ValueError, RecursionError) as exc:
        return False, f"envelope is not canonical JSON: {exc}"
    if len(wire_encoded) > MAX_ENVELOPE_BYTES:
        return False, "envelope exceeds the wire byte limit"

    if not require_signature:
        return True, "ok"
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    if not isinstance(envelope.signature, str) or not envelope.signature:
        return False, "envelope signature missing"
    try:
        signature = b64u_decode(envelope.signature)
        if len(signature) != 64 or b64u_encode(signature) != envelope.signature:
            return False, "envelope signature invalid"
        key_hex = decode_ed25519_did_key_hex(envelope.sender_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(
            canonical_json(envelope.signing_body()), signature,
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError, DIDKeyError):
        return False, "envelope signature verification failed"
    return True, "ok"


def _content_address(envelope: TransportEnvelope) -> str:
    body = canonical_json(envelope.content_body())
    return "sha256:" + hashlib.sha256(body).hexdigest()


def new_nonce(length: int = 32) -> str:
    """Return a cryptographically random alphanumeric nonce."""

    if not 16 <= length <= 128:
        raise ValueError("nonce length must be 16..128")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def sign_envelope(
    identity: AgentIdentity,
    *,
    kind: str,
    recipient: str,
    payload: Dict[str, Any],
    created_at_ms: int,
    expires_at_ms: int,
    dao_id: Optional[str] = None,
    reply_to: str = "",
    hop_limit: int = DEFAULT_HOP_LIMIT,
    nonce: Optional[str] = None,
) -> TransportEnvelope:
    """Build and sign one envelope. Raises TransportEnvelopeRejected."""

    routing: Dict[str, Any] = {"hop_limit": hop_limit, "hop_count": 0}
    if reply_to:
        routing["reply_to"] = reply_to
    if not isinstance(payload, dict):
        raise TransportEnvelopeRejected("payload must be an object")
    try:
        payload_hash = _payload_digest(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise TransportEnvelopeRejected(
            f"payload is not canonical JSON: {exc}"
        ) from exc
    envelope = TransportEnvelope(
        message_id="",
        kind=kind,
        sender_did=identity.as_did(),
        recipient=recipient,
        dao_id=dao_id,
        created_at_ms=created_at_ms,
        expires_at_ms=expires_at_ms,
        nonce=nonce or new_nonce(),
        payload_hash=payload_hash,
        payload=payload,
        routing=routing,
        signature="",
    )
    envelope.message_id = _content_address(envelope)
    ok, reason = _validate_envelope(envelope, require_signature=False)
    if not ok:
        raise TransportEnvelopeRejected(reason)
    envelope.signature = b64u_encode(identity.sign(canonical_json(envelope.signing_body())))
    ok, reason = _validate_envelope(envelope)
    if not ok:
        raise TransportEnvelopeRejected(reason)
    return envelope


def validate_envelope(
    envelope: TransportEnvelope,
    *,
    now_ms: Optional[int] = None,
    require_signature: bool = True,
) -> tuple[bool, str]:
    """Public validation entry point; returns (ok, reason)."""

    return _validate_envelope(envelope, now_ms=now_ms, require_signature=require_signature)


def envelope_digest(envelope: Union[TransportEnvelope, Dict[str, Any]]) -> str:
    """Content digest of the canonical wire bytes of one envelope.

    When handed a plain dict, the field set must be an exact envelope
    projection (round-19 bug FF-5: previously any dict was digested
    unchecked, letting callers compute digests over malformed shapes and
    bind them into ACKs and outbox records).
    """

    if isinstance(envelope, TransportEnvelope):
        wire = _recode_envelope(envelope)
    else:
        if frozenset(envelope) not in TransportEnvelope.allowed_field_sets():
            raise TransportEnvelopeRejected(
                "envelope dict has missing or unknown fields"
            )
        wire = envelope
    return "sha256:" + hashlib.sha256(canonical_json(wire)).hexdigest()


def forward_envelope(envelope: TransportEnvelope) -> TransportEnvelope:
    """Return the relay-forwarded copy: hop_count + 1, signature untouched.

    Fails closed when the hop budget is exhausted. Everything the author
    signed stays byte-identical; only the mutable hop counter moves.
    """

    ok, reason = _validate_envelope(envelope)
    if not ok:
        raise TransportEnvelopeRejected(reason)
    hop_count = envelope.routing["hop_count"]
    hop_limit = envelope.routing["hop_limit"]
    if hop_count + 1 > hop_limit:
        raise TransportEnvelopeRejected("hop budget exhausted")
    routing = dict(envelope.routing)
    routing["hop_count"] = hop_count + 1
    forwarded = TransportEnvelope(
        message_id=envelope.message_id,
        kind=envelope.kind,
        sender_did=envelope.sender_did,
        recipient=envelope.recipient,
        dao_id=envelope.dao_id,
        created_at_ms=envelope.created_at_ms,
        expires_at_ms=envelope.expires_at_ms,
        nonce=envelope.nonce,
        payload_hash=envelope.payload_hash,
        payload=envelope.payload,
        routing=routing,
        signature=envelope.signature,
    )
    ok, reason = _validate_envelope(forwarded)
    if not ok:  # pragma: no cover - defensive
        raise TransportEnvelopeRejected(reason)
    return forwarded


__all__ = [
    "DEFAULT_HOP_LIMIT",
    "ENVELOPE_PROTOCOL",
    "ENVELOPE_VERSION",
    "MAX_CLOCK_SKEW_MS",
    "MAX_ENVELOPE_BYTES",
    "MAX_HOP_LIMIT",
    "MAX_PAYLOAD_BYTES",
    "MAX_PAYLOAD_DEPTH",
    "MAX_SAFE_INTEGER",
    "MAX_TTL_MS",
    "TransportEnvelope",
    "TransportEnvelopeRejected",
    "envelope_digest",
    "forward_envelope",
    "new_nonce",
    "sign_envelope",
    "validate_envelope",
]
