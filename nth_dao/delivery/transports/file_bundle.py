"""Signed file-bundle transport, the cheapest true-offline baseline.

One ``send`` writes ONE self-contained bundle file into the exchange
directory::

    {"protocol":   "nth-delivery-file-bundle",
     "version":    1,
     "sender_did": "did:key:...",
     "created_at_ms": 1750000000000,
     "envelopes":  ["<canonical envelope json>", ...],
     "envelopes_sha256": "sha256:<digest over the concatenated lines>",
     "signature":  "<b64url Ed25519 by sender_did>"}

``poll`` scans the exchange directory, verifies the bundle signature and
every envelope digest, and returns the parsed envelopes. Already-imported
bundles are recorded in a persistent journal (digest-keyed) so a re-scan of
the same USB stick never double-delivers. Every bundle is defense in depth:
the inbox re-validates each envelope independently.

Threat model notes (design doc §10): a hostile courier can drop, duplicate,
reorder, or corrupt bundles — duplication is handled by the import journal,
corruption by digest/signature checks, dropping is inherent to store-and-
carry and surfaced as non-delivery, not as an error.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional, Union

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
    TransportEnvelopeRejected,
    validate_envelope,
)
from nth_dao.delivery.transports.base import (
    PRIVACY_LOCAL,
    SendResult,
    Transport,
    TransportCapabilities,
)
from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key,
    decode_ed25519_did_key_hex,
    is_did_key,
)
from nth_dao.identity import _NACL_AVAILABLE, AgentIdentity
from nth_dao.util.io import InterProcessLock

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]

logger = logging.getLogger("nth_dao.delivery")

BUNDLE_PROTOCOL = "nth-delivery-file-bundle"
BUNDLE_VERSION = 1
BUNDLE_SUFFIX = ".nthbundle"
BUNDLE_MAX_BUNDLES_PER_DIR = 4_096
BUNDLE_MAX_ENVELOPES = 256
BUNDLE_MAX_FILE_BYTES = 64 * 1024 * 1024
_IMPORTED_JOURNAL = "imported.jsonl"
_IMPORTED_JOURNAL_CAP = 1024 * 1024

_BUNDLE_FIELDS = (
    "protocol",
    "version",
    "sender_did",
    "created_at_ms",
    "envelopes",
    "envelopes_sha256",
    "signature",
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class FileBundleRejected(ValueError):
    """Raised when a bundle cannot be built, signed, or verified."""


def _bundle_body(bundle: dict) -> dict:
    return {key: value for key, value in bundle.items() if key != "signature"}


def _envelopes_digest(envelope_jsons: List[str]) -> str:
    hasher = hashlib.sha256()
    for envelope_json in envelope_jsons:
        hasher.update(envelope_json.encode("utf-8"))
        hasher.update(b"\n")
    return "sha256:" + hasher.hexdigest()


class FileBundleTransport(Transport):
    """Exchange-directory transport for offline, human-carried delivery."""

    def __init__(
        self,
        exchange_dir: Union[str, Path],
        identity: AgentIdentity,
        *,
        state_dir: Optional[Union[str, Path]] = None,
        clock: Optional[Callable[[], int]] = None,
        name: str = "file-bundle",
    ) -> None:
        if not _NACL_AVAILABLE or _VerifyKey is None:
            raise FileBundleRejected("crypto unavailable: PyNaCl is required")
        self._exchange_dir = Path(exchange_dir)
        self._state_dir = Path(state_dir) if state_dir else self._exchange_dir / ".state"
        self._imported_path = self._state_dir / _IMPORTED_JOURNAL
        self._identity = identity
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._lock = threading.RLock()
        self._imported: set[str] = set()
        self._imported_stat: Optional[tuple] = None
        self.capabilities = TransportCapabilities(
            name=name,
            unicast=False,
            broadcast=True,
            realtime=False,
            privacy_level=PRIVACY_LOCAL,
            external_infrastructure=False,
            ack_mode="none",
        )
        self._exchange_dir.mkdir(parents=True, exist_ok=True)
        self._state_dir.mkdir(parents=True, exist_ok=True)
        with InterProcessLock(self._imported_path):
            self._load_imported()

    # ─────────────────────── Transport API ───────────────────────

    def send(self, envelope: TransportEnvelope) -> SendResult:
        ok, reason = validate_envelope(envelope, require_signature=True)
        if not ok:
            return SendResult(accepted=False, error_code="invalid-envelope")
        try:
            bundle = self._build_bundle([envelope])
        except FileBundleRejected as exc:
            return SendResult(accepted=False, error_code=f"bundle-error: {exc}")
        try:
            self._write_bundle(bundle)
        except OSError as exc:
            logger.warning("file bundle write failed: %s", exc)
            return SendResult(accepted=False, error_code="exchange-dir-unwritable")
        return SendResult(accepted=True)

    def poll(self, *, max_items: int = 64) -> List[TransportEnvelope]:
        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
            raise ValueError("max_items must be a positive integer")
        envelopes: List[TransportEnvelope] = []
        for bundle_path in sorted(self._exchange_dir.glob(f"*{BUNDLE_SUFFIX}")):
            if len(envelopes) >= max_items:
                break
            try:
                # stat BEFORE read: a hostile courier can drop arbitrarily
                # large files; never pull one into memory unread
                if bundle_path.stat().st_size > BUNDLE_MAX_FILE_BYTES:
                    logger.warning("bundle %s exceeds the size limit; skipping", bundle_path.name)
                    continue
                raw = bundle_path.read_bytes()
                # re-check after read: the file could have been swapped for a
                # larger one between stat and open (round-4 bug S)
                if len(raw) > BUNDLE_MAX_FILE_BYTES:
                    logger.warning("bundle %s grew past the size limit; skipping", bundle_path.name)
                    continue
            except OSError as exc:
                logger.warning("cannot read bundle %s: %s", bundle_path.name, exc)
                continue
            try:
                bundle = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("bundle %s is not valid JSON; skipping", bundle_path.name)
                continue
            digest = self._verify_bundle(bundle)
            if digest is None:
                continue
            for envelope_json in bundle["envelopes"]:
                if len(envelopes) >= max_items:
                    break
                try:
                    parsed = json.loads(envelope_json)
                    envelope = TransportEnvelope.from_dict(parsed)
                except (json.JSONDecodeError, TransportEnvelopeRejected, TypeError):
                    logger.warning("bundle %s holds a malformed envelope; skipping it", bundle_path.name)
                    continue
                with self._lock:
                    with InterProcessLock(self._imported_path):
                        self._refold_imported_if_changed()
                        # Legacy journals recorded the whole bundle digest;
                        # new journals record each message independently so
                        # max_items pagination cannot discard the tail.
                        if digest in self._imported:
                            break
                        if envelope.message_id in self._imported:
                            continue
                        self._append_imported_locked(envelope.message_id)
                        self._imported.add(envelope.message_id)
                envelopes.append(envelope)
        return envelopes

    def health(self):
        from nth_dao.delivery.transports.base import TransportHealth

        return TransportHealth(reachable=self._exchange_dir.exists())

    # ─────────────────────── bundle internals ───────────────────────

    def _build_bundle(self, envelopes: List[TransportEnvelope]) -> dict:
        envelope_jsons: List[str] = []
        for envelope in envelopes:
            envelope_jsons.append(canonical_json(envelope.to_dict()).decode("utf-8"))
        if not envelope_jsons or len(envelope_jsons) > BUNDLE_MAX_ENVELOPES:
            raise FileBundleRejected("bundle must hold 1..256 envelopes")
        for envelope_json in envelope_jsons:
            if len(envelope_json.encode("utf-8")) > MAX_ENVELOPE_BYTES:
                raise FileBundleRejected("envelope exceeds the wire limit")
        bundle = {
            "protocol": BUNDLE_PROTOCOL,
            "version": BUNDLE_VERSION,
            "sender_did": self._identity.as_did(),
            "created_at_ms": self._clock(),
            "envelopes": envelope_jsons,
            "envelopes_sha256": _envelopes_digest(envelope_jsons),
        }
        bundle["signature"] = b64u_encode(
            self._identity.sign(canonical_json(_bundle_body(bundle)))
        )
        return bundle

    def _write_bundle(self, bundle: dict) -> None:
        stamp = bundle["created_at_ms"]
        nonce = bundle["envelopes_sha256"][-12:]
        path = self._exchange_dir / f"bundle-{stamp}-{nonce}{BUNDLE_SUFFIX}"
        # unique tmp name: two processes must never share one temp file
        tmp = self._exchange_dir / (
            f".tmp-{stamp}-{nonce}-{os.getpid()}-{secrets.token_hex(4)}"
        )
        try:
            with open(tmp, "wb") as handle:
                handle.write(canonical_json(bundle))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise

    def _verify_bundle(self, bundle: object) -> Optional[str]:
        """Verify one parsed bundle; returns its digest, or None (with log)."""

        if not isinstance(bundle, dict) or frozenset(bundle) != frozenset(_BUNDLE_FIELDS):
            logger.warning("bundle has missing or unknown fields; rejecting")
            return None
        version = bundle["version"]
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or bundle["protocol"] != BUNDLE_PROTOCOL
            or version != BUNDLE_VERSION
        ):
            logger.warning("bundle protocol/version mismatch; rejecting")
            return None
        sender_did = bundle["sender_did"]
        if not is_did_key(sender_did) or not isinstance(sender_did, str):
            logger.warning("bundle sender_did invalid; rejecting")
            return None
        try:
            decode_ed25519_did_key(sender_did)
        except (DIDKeyError, ValueError, TypeError):
            logger.warning("bundle sender_did undecodable; rejecting")
            return None
        envelopes = bundle["envelopes"]
        if not isinstance(envelopes, list) or not envelopes or len(envelopes) > BUNDLE_MAX_ENVELOPES:
            logger.warning("bundle envelope list invalid; rejecting")
            return None
        for envelope_json in envelopes:
            if (
                not isinstance(envelope_json, str)
                or len(envelope_json.encode("utf-8")) > MAX_ENVELOPE_BYTES
            ):
                logger.warning("bundle holds an oversized envelope; rejecting")
                return None
            try:
                parsed = json.loads(envelope_json)
                envelope = TransportEnvelope.from_dict(parsed)
            except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
                logger.warning("bundle holds a malformed envelope; rejecting")
                return None
            if canonical_json(envelope.to_dict()).decode("utf-8") != envelope_json:
                logger.warning("bundle envelope is not canonical JSON; rejecting")
                return None
            ok, _reason = validate_envelope(envelope, require_signature=True)
            if not ok:
                logger.warning("bundle holds an invalid envelope; rejecting")
                return None
        if bundle["envelopes_sha256"] != _envelopes_digest(envelopes):
            logger.warning("bundle digest mismatch; rejecting")
            return None
        if not _NACL_AVAILABLE or _VerifyKey is None:  # pragma: no cover
            logger.warning("crypto unavailable; rejecting bundle")
            return None
        try:
            signature = b64u_decode(bundle["signature"])
            if len(signature) != 64 or b64u_encode(signature) != bundle["signature"]:
                raise FileBundleRejected("bad signature encoding")
            key_hex = decode_ed25519_did_key_hex(sender_did) or ""
            _VerifyKey(bytes.fromhex(key_hex)).verify(
                canonical_json(_bundle_body(bundle)), signature,
            )
        except (_BadSignatureError, TypeError, ValueError, UnicodeError, DIDKeyError):
            logger.warning("bundle signature verification failed; rejecting")
            return None
        return bundle["envelopes_sha256"]

    def _load_imported(self) -> None:
        if not self._imported_path.exists():
            self._imported_stat = None
            return
        stat = self._imported_path.stat()
        self._imported_stat = (stat.st_mtime_ns, stat.st_size)
        raw = self._imported_path.read_bytes()
        torn = bool(raw) and not raw.endswith(b"\n")
        lines = raw.split(b"\n")
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            if index == len(lines) - 1 and torn:
                logger.warning("import journal has a torn final line; ignoring it")
                break
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise FileBundleRejected(f"corrupt import journal: {exc}") from exc
            digest = None
            if isinstance(event, dict):
                digest = event.get("message_id", event.get("envelopes_sha256"))
            if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                raise FileBundleRejected("import journal digest invalid")
            self._imported.add(digest)

    def _refold_imported_if_changed(self) -> None:
        """Re-fold the import journal when another process imported into the
        shared state dir (same stat-check pattern as inbox/outbox)."""

        try:
            if not self._imported_path.exists():
                return
            stat = self._imported_path.stat()
        except OSError:
            return
        current = (stat.st_mtime_ns, stat.st_size)
        if current != self._imported_stat:
            self._imported = set()
            self._load_imported()

    def _append_imported_locked(self, message_id: str) -> None:
        import os

        with open(self._imported_path, "ab") as handle:
            handle.write(
                canonical_json({"message_id": message_id, "at_ms": self._clock()})
                + b"\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
            stat = os.fstat(handle.fileno())
            self._imported_stat = (stat.st_mtime_ns, stat.st_size)
        # The caller still holds the process lock while rotation replaces
        # the journal, so a concurrent import cannot be lost.
        if self._imported_path.stat().st_size > _IMPORTED_JOURNAL_CAP:
            lines = self._imported_path.read_bytes().splitlines()
            keep = lines[-max(1, len(lines) // 2):]
            tmp = self._imported_path.with_suffix(
                f".jsonl.{os.getpid()}-{secrets.token_hex(4)}.tmp"
            )
            with open(tmp, "wb") as handle:
                for line in keep:
                    handle.write(line + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._imported_path)
            retained: set[str] = set()
            for line in keep:
                event = json.loads(line)
                imported_id = event.get("message_id", event.get("envelopes_sha256"))
                if not isinstance(imported_id, str) or _SHA256_RE.fullmatch(imported_id) is None:
                    raise FileBundleRejected("import journal digest invalid after rotation")
                retained.add(imported_id)
            self._imported = retained
            logger.warning(
                "import journal exceeded %d bytes; rotated to %d entries",
                _IMPORTED_JOURNAL_CAP,
                len(keep),
            )


__all__ = [
    "BUNDLE_MAX_ENVELOPES",
    "BUNDLE_PROTOCOL",
    "BUNDLE_VERSION",
    "FileBundleRejected",
    "FileBundleTransport",
]
