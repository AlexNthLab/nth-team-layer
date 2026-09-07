"""Signed delivery acknowledgements (ACK) for the delivery layer.

An ACK is a small signed statement by the *receiver* that one specific
envelope arrived. It binds the exact wire bytes seen on the wire:

* ``message_id`` — the content address of the delivered envelope;
* ``envelope_sha256`` — the digest of the canonical bytes as received, so a
  relay-mangled copy cannot be acknowledged as the author's original.

Senders treat a valid ACK as authoritative delivery evidence for one
transport copy of a message and may cancel other in-flight copies. The ACK
carries no authority beyond delivery: it never implies business acceptance,
claim success, or payment.

Fail-closed rules mirror ``envelope.py``: exact field sets, canonical JSON,
no floats, bounded integers, strict b64url signatures, receiver must be a
decodable Ed25519 did:key, and future-dated ACKs beyond clock skew are
rejected.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import MAX_CLOCK_SKEW_MS, MAX_SAFE_INTEGER
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

ACK_PROTOCOL = "nth-delivery-ack"
ACK_VERSION = 1
ACK_KIND = "delivery.ack"
ACK_STATUS_RECEIVED = "received"
ACK_STATUSES = (ACK_STATUS_RECEIVED,)
MAX_ACK_BYTES = 16 * 1024

_MESSAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_ACK_FIELDS = (
    "protocol",
    "version",
    "kind",
    "message_id",
    "envelope_sha256",
    "receiver_did",
    "status",
    "received_at_ms",
    "signature",
)


class DeliveryAckRejected(ValueError):
    """Raised when an ACK cannot be built or fails validation."""


@dataclass
class DeliveryAck:
    """One signed delivery receipt for one envelope."""

    message_id: str
    envelope_sha256: str
    receiver_did: str
    received_at_ms: int
    signature: str = ""
    protocol: str = ACK_PROTOCOL
    version: int = ACK_VERSION
    kind: str = ACK_KIND
    status: str = ACK_STATUS_RECEIVED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signing_body(self) -> Dict[str, Any]:
        return {
            key: value for key, value in self.to_dict().items() if key != "signature"
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "DeliveryAck":
        if not isinstance(value, dict):
            raise DeliveryAckRejected("ack must be a JSON object")
        if frozenset(value) != frozenset(_ACK_FIELDS):
            raise DeliveryAckRejected("ack has missing or unknown fields")
        try:
            return cls(**value)
        except TypeError as exc:  # pragma: no cover - guarded by field-set check
            raise DeliveryAckRejected(f"malformed ack: {exc}") from exc


def _validate_ack(
    ack: DeliveryAck,
    *,
    now_ms: Optional[int] = None,
    require_signature: bool = True,
) -> tuple[bool, str]:
    if not isinstance(ack, DeliveryAck):
        return False, "ack must be a DeliveryAck"
    if ack.protocol != ACK_PROTOCOL:
        return False, "wrong ack protocol"
    if (
        isinstance(ack.version, bool)
        or not isinstance(ack.version, int)
        or ack.version != ACK_VERSION
    ):
        return False, "unsupported ack version"
    if ack.kind != ACK_KIND:
        return False, "wrong ack kind"
    if ack.status not in ACK_STATUSES:
        return False, "unsupported ack status"

    if not isinstance(ack.message_id, str) or _MESSAGE_ID_RE.fullmatch(ack.message_id) is None:
        return False, "message_id is not a content address"
    if not isinstance(ack.envelope_sha256, str) or _SHA256_RE.fullmatch(ack.envelope_sha256) is None:
        return False, "envelope_sha256 is not a content address"

    if not is_did_key(ack.receiver_did):
        return False, "invalid receiver DID"
    try:
        decode_ed25519_did_key(ack.receiver_did)
    except (DIDKeyError, ValueError, TypeError) as exc:
        return False, f"receiver DID is not a decodable Ed25519 did:key: {exc}"

    if isinstance(ack.received_at_ms, bool) or not isinstance(ack.received_at_ms, int):
        return False, "received_at_ms must be an integer"
    if not 0 < ack.received_at_ms <= MAX_SAFE_INTEGER:
        return False, "received_at_ms out of range"
    if now_ms is not None:
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            return False, "now_ms must be an integer"
        if not 0 < now_ms <= MAX_SAFE_INTEGER:
            return False, "now_ms out of range"
        if ack.received_at_ms > now_ms + MAX_CLOCK_SKEW_MS:
            return False, "ack dated in the future beyond clock skew"

    try:
        wire = canonical_json(ack.to_dict())
    except (TypeError, ValueError, RecursionError) as exc:
        return False, f"ack is not canonical JSON: {exc}"
    if len(wire) > MAX_ACK_BYTES:
        return False, "ack exceeds the wire byte limit"

    if not require_signature:
        return True, "ok"
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    if not isinstance(ack.signature, str) or not ack.signature:
        return False, "ack signature missing"
    try:
        signature = b64u_decode(ack.signature)
        if len(signature) != 64 or b64u_encode(signature) != ack.signature:
            return False, "ack signature invalid"
        key_hex = decode_ed25519_did_key_hex(ack.receiver_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(
            canonical_json(ack.signing_body()), signature,
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, "ack signature verification failed"
    return True, "ok"


def sign_ack(
    identity: AgentIdentity,
    *,
    message_id: str,
    envelope_sha256: str,
    received_at_ms: int,
) -> DeliveryAck:
    """Build and sign one ACK as the receiving identity."""

    ack = DeliveryAck(
        message_id=message_id,
        envelope_sha256=envelope_sha256,
        receiver_did=identity.as_did(),
        received_at_ms=received_at_ms,
    )
    ok, reason = _validate_ack(ack, require_signature=False)
    if not ok:
        raise DeliveryAckRejected(reason)
    ack.signature = b64u_encode(identity.sign(canonical_json(ack.signing_body())))
    ok, reason = _validate_ack(ack)
    if not ok:
        raise DeliveryAckRejected(reason)
    return ack


def validate_ack(
    ack: DeliveryAck,
    *,
    now_ms: Optional[int] = None,
    require_signature: bool = True,
) -> tuple[bool, str]:
    """Public validation entry point; returns (ok, reason)."""

    return _validate_ack(ack, now_ms=now_ms, require_signature=require_signature)


def ack_digest(ack: DeliveryAck) -> str:
    """Content digest of one ACK's canonical wire bytes."""

    return "sha256:" + hashlib.sha256(canonical_json(ack.to_dict())).hexdigest()


__all__ = [
    "ACK_KIND",
    "ACK_PROTOCOL",
    "ACK_STATUSES",
    "ACK_STATUS_RECEIVED",
    "ACK_VERSION",
    "DeliveryAck",
    "DeliveryAckRejected",
    "ack_digest",
    "sign_ack",
    "validate_ack",
]
