"""HTTPS federation transport — push signed envelopes to known peer nodes.

Phase 1 of the integration design doc §8.1: "已知节点 ... HTTPS federation".
Borrowing rule: the URL policy mirrors ``nth_dao.commerce.outbox``
(``_normalize_target_url``), the bounded HTTP style mirrors
``nth_dao.integrations.node_client`` (urllib + strict timeout + capped
response reads), and the ingest server is plain stdlib ``http.server`` so the
core stays zero-dependency (a FastAPI route can wrap the same handler later).

Model:

* ``FederationTransport`` — client: POST the canonical envelope bytes to
  every configured peer ``.../delivery/ingest``; accepted when at least one
  peer accepts. Push-only; ``poll`` is always empty (inbound envelopes
  arrive at YOUR ingest server).
* ``FederationIngestServer`` — stdlib threading HTTP server feeding a
  ``DeliveryInbox``. Bounds: exact path, Content-Length required and capped,
  canonical-bytes discipline, bounded response bodies, per-connection
  timeouts, bounded accept queue. The inbox performs the full fail-closed
  validation — the server is an untrusted-input front door, nothing more.
* The receiver's signed ACK travels back as an ordinary envelope
  (``kind="delivery.ack"``, payload ``{"ack": {...}}``) — see
  ``ack_from_envelope`` in ``nth_dao.delivery.acknowledgement``. Everything
  on the wire is an envelope; hosts unwrap ACKs after inbox validation.
"""

from __future__ import annotations

import http.server
import json
import logging
import math
import socketserver
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import (
    ACK_KIND,
    DeliveryAck,
    validate_ack,
)
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
    validate_envelope,
)
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.did_key import is_did_key
from nth_dao.delivery.transports.base import (
    PRIVACY_PEER,
    SendResult,
    Transport,
    TransportCapabilities,
    TransportHealth,
)

logger = logging.getLogger("nth_dao.delivery")

INGEST_PATH = "/delivery/ingest"
MAX_PEER_URLS = 64
MAX_PEER_URL_CHARS = 2048
DEFAULT_TIMEOUT = 5.0
MAX_RESPONSE_BYTES = 64 * 1024
BODY_SLACK_BYTES = 64 * 1024
ACCEPTED_STATUSES = (200, 202)


class FederationTransportError(ValueError):
    """Raised when a peer URL or configuration is invalid."""


def validate_peer_url(value: str) -> str:
    """Accept https anywhere; plain http only for loopback test hosts.

    Mirrors ``nth_dao.commerce.outbox._normalize_target_url``: no credentials,
    no query, no fragment, bounded length. Federation envelopes are signed by
    their author, but the transport still refuses credential-bearing URLs so
    secrets never land in logs or federation state.
    """

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > MAX_PEER_URL_CHARS
        or any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in value
        )
    ):
        raise FederationTransportError("invalid peer URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise FederationTransportError("invalid peer URL") from exc
    hostname = (parsed.hostname or "").lower()
    is_loopback = hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "https":
        pass
    elif parsed.scheme == "http" and is_loopback:
        pass  # loopback http is the test/local federation baseline
    else:
        raise FederationTransportError(
            "peer URL must be https (http only allowed for loopback hosts)"
        )
    if (
        not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise FederationTransportError("invalid peer URL")
    return value.rstrip("/")


def _http_post_bytes(
    url: str,
    body: bytes,
    *,
    timeout: float,
    max_response_bytes: int,
    verify_tls: bool,
) -> Tuple[int, bytes]:
    """Bounded POST: strict timeout, capped response, no redirects followed."""

    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    opener: urllib.request.OpenerDirector = urllib.request.build_opener(
        _NoRedirect(),
        *([] if verify_tls else [_InsecureTLS()]),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            raw = response.read(max_response_bytes + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read(max_response_bytes + 1) if exc.fp else b""
    return status, raw


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class _InsecureTLS(urllib.request.HTTPSHandler):
    """TLS-disabled handler for ``verify_tls=False`` transports."""

    _context = None  # built once; context creation per POST is pure waste

    def __init__(self) -> None:
        import ssl

        if _InsecureTLS._context is None:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            _InsecureTLS._context = context
        super().__init__(context=_InsecureTLS._context)


class FederationTransport(Transport):
    """Push signed envelopes to configured federation peers over HTTPS."""

    def __init__(
        self,
        *,
        peer_urls: Optional[List[str]] = None,
        recipient_urls: Optional[Dict[str, str]] = None,
        name: str = "federation-https",
        timeout: float = DEFAULT_TIMEOUT,
        verify_tls: bool = True,
    ) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 0.1 <= float(timeout) <= 30.0
        ):
            raise ValueError("timeout must be between 0.1 and 30 seconds")
        if peer_urls is not None and not isinstance(peer_urls, list):
            raise ValueError("peer_urls must be a list")
        if recipient_urls is not None and not isinstance(recipient_urls, dict):
            raise ValueError("recipient_urls must be a DID-to-URL mapping")
        peer_urls = peer_urls or []
        recipient_urls = recipient_urls or {}
        if not peer_urls and not recipient_urls:
            raise ValueError("peer_urls or recipient_urls must contain a route")
        if len(peer_urls) + len(recipient_urls) > MAX_PEER_URLS:
            raise ValueError(f"federation routes are capped at {MAX_PEER_URLS}")
        if not isinstance(verify_tls, bool):
            raise ValueError("verify_tls must be a boolean")
        self._peers = [validate_peer_url(url) + INGEST_PATH for url in peer_urls]
        if len(set(self._peers)) != len(self._peers):
            raise ValueError("peer_urls must not contain duplicates")
        self._recipient_routes: Dict[str, str] = {}
        for recipient_did, url in recipient_urls.items():
            if not isinstance(recipient_did, str) or not is_did_key(recipient_did):
                raise ValueError("recipient_urls keys must be Ed25519 did:key values")
            self._recipient_routes[recipient_did] = validate_peer_url(url) + INGEST_PATH
        self._timeout = float(timeout)
        self._verify_tls = verify_tls
        self.capabilities = TransportCapabilities(
            name=name,
            unicast=bool(self._recipient_routes),
            broadcast=True,
            realtime=False,
            privacy_level=PRIVACY_PEER,
            external_infrastructure=False,
            ack_mode="host",
        )

    def send(self, envelope: TransportEnvelope) -> SendResult:
        # signature/integrity validated here; the TTL window is the
        # receiver's inbox decision (its clock) — see the gossip adapter note
        ok, reason = validate_envelope(envelope, require_signature=True)
        if not ok:
            return SendResult(accepted=False, error_code=f"invalid-envelope: {reason}")
        if envelope.recipient.startswith("did:key:"):
            direct_url = self._recipient_routes.get(envelope.recipient)
            if direct_url is None:
                return SendResult(
                    accepted=False, error_code="recipient-route-required"
                )
            target_urls = [direct_url]
        else:
            target_urls = list(
                dict.fromkeys([*self._peers, *self._recipient_routes.values()])
            )
        body = canonical_json(envelope.to_dict())
        accepted_any = False
        # the per-peer timeout bounds one POST; this overall budget bounds the
        # whole fan-out so a long peer list cannot stall a send for minutes
        overall_deadline = time.monotonic() + self._timeout * 4
        for index, url in enumerate(target_urls):
            if time.monotonic() > overall_deadline:
                skipped = len(target_urls) - index
                logger.warning("federation fan-out deadline exceeded; %d peers skipped",
                               skipped)
                break
            try:
                status, _raw = _http_post_bytes(
                    url,
                    body,
                    timeout=self._timeout,
                    max_response_bytes=MAX_RESPONSE_BYTES,
                    verify_tls=self._verify_tls,
                )
            except (urllib.error.URLError, OSError, ValueError) as exc:
                logger.warning("federation peer %s unreachable: %s", url, exc)
                continue
            if status in ACCEPTED_STATUSES:
                accepted_any = True
            else:
                logger.warning("federation peer %s rejected with status %s", url, status)
        if accepted_any:
            return SendResult(accepted=True)
        return SendResult(accepted=False, error_code="peers-unreachable")

    def poll(self, *, max_items: int = 64) -> List[TransportEnvelope]:
        """Push model: inbound envelopes arrive at your ingest server."""
        return []

    def health(self) -> TransportHealth:
        return TransportHealth(
            reachable=bool(self._peers or self._recipient_routes)
        )


class _IngestHandler(http.server.BaseHTTPRequestHandler):
    """Bounded envelope ingest front door; validation lives in the inbox."""

    server_version = "nth-dao-delivery/1"
    protocol_version = "HTTP/1.1"
    timeout = 10  # per-connection socket timeout

    @property
    def _inbox(self) -> DeliveryInbox:
        return self.server.inbox  # type: ignore[attr-defined]

    @property
    def _max_body(self) -> int:
        return self.server.max_body  # type: ignore[attr-defined]

    def _respond(self, status: int, payload: dict) -> None:
        body = canonical_json(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        # concurrency gate: ThreadingMixIn spawns a thread per connection, so
        # without a bound a connection flood exhausts threads/memory. Beyond
        # the gate we answer 503 immediately (round-1 Phase-1 hardening).
        if not self.server.gate.acquire(blocking=False):  # type: ignore[attr-defined]
            self._respond(503, {"accepted": False, "reason": "server busy"})
            self.close_connection = True
            return
        try:
            self._do_post()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        finally:
            self.server.gate.release()  # type: ignore[attr-defined]

    def _do_post(self) -> None:
        if self.path != INGEST_PATH:
            self._respond(404, {"accepted": False, "reason": "unknown path"})
            return
        transfer_encoding = self.headers.get("Transfer-Encoding")
        content_lengths = self.headers.get_all("Content-Length", failobj=[])
        if transfer_encoding is not None or len(content_lengths) != 1:
            self._respond(400, {"accepted": False, "reason": "ambiguous body framing"})
            self.close_connection = True
            return
        raw_length = content_lengths[0]
        # strict ASCII digits: unicode isdigit() chars like the superscript ²
        # pass isdigit() but explode int() (round-8 review bug AJ)
        if raw_length is None or not (raw_length.isascii() and raw_length.isdigit()):
            self._respond(400, {"accepted": False, "reason": "Content-Length required"})
            return
        length = int(raw_length)
        if length <= 0 or length > self._max_body:
            # drain a bounded amount so the client can still read our 413
            # instead of a TCP reset; anything beyond the drain bound keeps
            # the reset (unavoidable, and the sender gets no useful answer
            # for bodies that large anyway)
            self._drain(length)
            self._respond(413, {"accepted": False, "reason": "body size out of bounds"})
            self.close_connection = True
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._respond(400, {"accepted": False, "reason": "incomplete request body"})
            self.close_connection = True
            return
        try:
            encoded = body.decode("utf-8")
        except UnicodeDecodeError:
            self._respond(400, {"accepted": False, "reason": "malformed envelope"})
            return
        try:
            json.loads(encoded)
        except (json.JSONDecodeError, RecursionError):
            self._respond(400, {"accepted": False, "reason": "malformed envelope"})
            return
        # Preserve the exact received representation. Passing a pre-parsed
        # object would bypass DeliveryInbox's canonical-wire check and make
        # duplicate-key or whitespace variants indistinguishable.
        decision = self._inbox.accept(encoded)
        if decision.accepted:
            self._respond(
                200,
                {"accepted": True, "message_id": decision.message_id},
            )
        elif decision.duplicate:
            # idempotent redelivery is a success for the sender
            self._respond(
                200,
                {"accepted": True, "duplicate": True, "message_id": decision.message_id},
            )
        else:
            self._respond(
                422,
                {"accepted": False, "reason": decision.reason[:512]},
            )

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        logger.debug("federation ingest: " + format, *args)

    def _drain(self, length: int, *, bound: int = 8 * 1024 * 1024) -> None:
        """Discard up to ``bound`` bytes of an oversized declared body."""

        remaining = min(length, bound)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65_536))
            if not chunk:
                break
            remaining -= len(chunk)


class FederationIngestServer:
    """Standards-library HTTP front door feeding one DeliveryInbox."""

    def __init__(
        self,
        inbox: DeliveryInbox,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        max_body: int = MAX_ENVELOPE_BYTES + BODY_SLACK_BYTES,
    ) -> None:
        if max_body <= 0:
            raise ValueError("max_body must be positive")
        self.inbox = inbox
        self.max_body = max_body

        class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True
            request_queue_size = 16

        self._httpd = _Server((host, port), _IngestHandler)
        self._httpd.inbox = inbox  # type: ignore[attr-defined]
        self._httpd.max_body = max_body  # type: ignore[attr-defined]
        self._httpd.gate = threading.BoundedSemaphore(32)  # type: ignore[attr-defined]
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        shown = "127.0.0.1" if host in {"0.0.0.0", "::"} else str(host)
        return f"http://{shown}:{port}"

    @property
    def ingest_url(self) -> str:
        return self.url + INGEST_PATH

    def start(self) -> None:
        if self._running:
            return
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="nth-federation-ingest",
            daemon=True,
        )
        self._thread.start()
        self._running = True

    def stop(self) -> None:
        if not self._running:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._running = False


def ack_from_envelope(envelope: TransportEnvelope) -> DeliveryAck:
    """Unwrap a signed ACK carried as ``kind="delivery.ack"`` envelope payload.

    The host calls this AFTER the inbox accepted the envelope. The inner ACK
    must carry a valid receiver signature, and the envelope author must BE
    the ACK receiver — an envelope signed by anyone else cannot vouch for
    their ACK.
    """

    if envelope.kind != ACK_KIND:
        raise ValueError("envelope is not a delivery.ack")
    payload = envelope.payload
    if not isinstance(payload, dict) or frozenset(payload) != {"ack"}:
        raise ValueError("delivery.ack payload must hold exactly one 'ack' object")
    try:
        ack = DeliveryAck.from_dict(payload["ack"])
    except ValueError as exc:
        raise ValueError(f"invalid ack inside envelope: {exc}") from exc
    if ack.receiver_did != envelope.sender_did:
        raise ValueError("ack receiver does not match the envelope author")
    ok, reason = validate_ack(ack)
    if not ok:
        raise ValueError(f"invalid ack signature: {reason}")
    return ack


__all__ = [
    "ACK_KIND",
    "INGEST_PATH",
    "MAX_PEER_URLS",
    "FederationIngestServer",
    "FederationTransport",
    "FederationTransportError",
    "ack_from_envelope",
    "validate_peer_url",
]
