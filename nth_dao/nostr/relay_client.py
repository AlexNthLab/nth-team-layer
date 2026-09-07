"""Sync Nostr relay client — background-loop bridge over the borrowed async
``nostr_sdk.Client`` (same bridge pattern as ``WebSocketGossipTransport``).

Publish semantics: ``publish`` sends one event and waits for the relay OK
(bounded), returning an honest accepted/error result. Subscribe semantics:
a filter-backed subscription delivers events into a bounded queue drained
by ``poll``. All wire machinery (JSON relay protocol, reconnection, EOSE)
is the borrowed layer's; this class adds only the sync bridge and NTH
bounds (relay count cap, publish timeout, queue cap).
"""

from __future__ import annotations

import asyncio
import logging
import math
import threading
from collections import deque
from typing import Any, Callable, List, Optional

from nth_dao.nostr import NostrAdapterUnavailable

try:  # pragma: no cover - importorskip in tests
    import nostr_sdk as _ns  # type: ignore[import-untyped]

    from nostr_sdk import Client as _Client
    from nostr_sdk import Filter as _Filter
    from nostr_sdk import Kind as _Kind
    from nostr_sdk import PublicKey as _PublicKey
    from nostr_sdk import SingleLetterTag as _SingleLetterTag
    _NOSTR_AVAILABLE = True
except ImportError:  # pragma: no cover
    _ns = None
    _Client = None
    _Filter = None
    _Kind = None
    _PublicKey = None
    _SingleLetterTag = None
    _NOSTR_AVAILABLE = False

logger = logging.getLogger("nth_dao.nostr")

MAX_RELAYS = 16
MAX_EVENT_QUEUE = 4_096
MAX_SEEN_EVENT_IDS = 8_192
MAX_SUBSCRIPTION_KINDS = 64
MAX_SUBSCRIPTION_AUTHORS = 1_024
_DEFAULT_PUBLISH_TIMEOUT = 10.0
_MAX_PUBLISH_TIMEOUT = 60.0


class NostrRelayError(RuntimeError):
    """Raised for relay client lifecycle and publish failures."""


def _validate_relay_url(value: str) -> str:
    """Relay URLs must be wss (ws only for loopback test hosts)."""

    from urllib.parse import urlsplit

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 2048
    ):
        raise ValueError("relay url must be non-empty text")
    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("relay url has an invalid port") from exc
    if parsed.scheme == "wss":
        pass
    elif parsed.scheme == "ws" and hostname in {"localhost", "127.0.0.1", "::1"}:
        pass
    else:
        raise ValueError("relay url must be wss (ws only for loopback)")
    if (
        not parsed.netloc
        or not hostname
        or parsed.username
        or parsed.password
        or "@" in parsed.netloc
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError("relay url must not carry credentials")
    return value.rstrip("/")


def _bounded_timeout(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field} must be a finite number")
    timeout = float(value)
    if not math.isfinite(timeout) or not 0.1 <= timeout <= _MAX_PUBLISH_TIMEOUT:
        raise ValueError(f"{field} must be within [0.1, 60]")
    return timeout


class NostrRelayClient:
    """Sync facade over the borrowed async relay pool client."""

    def __init__(
        self,
        keys: Any,
        *,
        relay_urls: List[str],
        name: str = "nostr-relay",
        publish_timeout: float = _DEFAULT_PUBLISH_TIMEOUT,
    ) -> None:
        if not _NOSTR_AVAILABLE:
            raise NostrAdapterUnavailable(
                "nostr support requires the optional extra: pip install nth-dao[nostr]"
            )
        if (
            not isinstance(relay_urls, list)
            or not relay_urls
            or len(relay_urls) > MAX_RELAYS
        ):
            raise ValueError(f"relay_urls must hold 1..{MAX_RELAYS} entries")
        self._relay_urls = [_validate_relay_url(url) for url in relay_urls]
        if len(set(self._relay_urls)) != len(self._relay_urls):
            raise ValueError("relay_urls must not contain duplicates")
        self._keys = keys
        self._publish_timeout = _bounded_timeout(
            publish_timeout, field="publish_timeout"
        )
        self.capabilities_name = name
        self._client = _Client()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()
        self._start_error: Optional[str] = None
        self._running = False
        self._lifecycle_lock = threading.RLock()
        self._queue: deque = deque(maxlen=MAX_EVENT_QUEUE)
        self._queue_lock = threading.Lock()
        self._dropped_events = 0
        self._stream_task: Optional[asyncio.Task[None]] = None
        self._subscription_id: Optional[str] = None

    # ─────────────────────── lifecycle ───────────────────────

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._running:
                return
            self._started.clear()
            self._start_error = None
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(
                target=self._run_loop,
                name=f"nth-nostr-{self.capabilities_name}",
                daemon=True,
            )
            self._thread.start()
            if not self._started.wait(timeout=15.0):
                self._shutdown_loop()
                raise NostrRelayError("nostr relay client failed to start within 15s")
            if self._start_error is not None:
                self._shutdown_loop()
                raise NostrRelayError(
                    f"nostr relay client failed to start: {self._start_error}"
                )
            self._running = True

    def _run_loop(self) -> None:
        loop = self._loop
        assert loop is not None
        asyncio.set_event_loop(loop)

        async def _boot() -> None:
            try:
                from nostr_sdk import RelayUrl as _RelayUrl

                for url in self._relay_urls:
                    await self._client.add_relay(_RelayUrl.parse(url))
                await self._client.connect()
                self._start_error = None
            except Exception as exc:  # noqa: BLE001 - surfaced via the event
                self._start_error = str(exc)
            finally:
                self._started.set()

        boot = loop.create_task(_boot())
        try:
            loop.run_forever()
        finally:
            boot.cancel()
            try:
                loop.run_until_complete(boot)
            except (asyncio.CancelledError, Exception):
                pass
            pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            loop.close()

    def _shutdown_loop(self) -> None:
        loop = self._loop
        self._loop = None
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def stop(self) -> None:
        with self._lifecycle_lock:
            if not self._running or self._loop is None:
                return
            try:
                stopper = asyncio.run_coroutine_threadsafe(
                    self._stop_async(), self._loop
                )
                stopper.result(timeout=5.0)
            except Exception as exc:  # noqa: BLE001 - stop must never raise
                logger.warning("nostr relay disconnect failed: %s", exc)
            finally:
                self._running = False
                self._shutdown_loop()

    async def _stop_async(self) -> None:
        stream_task = self._stream_task
        self._stream_task = None
        if stream_task is not None and not stream_task.done():
            stream_task.cancel()
            try:
                await stream_task
            except asyncio.CancelledError:
                pass
        subscription_id = self._subscription_id
        self._subscription_id = None
        if subscription_id is not None:
            try:
                await self._client.unsubscribe(subscription_id)
            except Exception as exc:  # noqa: BLE001 - disconnect still must proceed
                logger.debug("nostr unsubscribe during stop failed: %s", exc)
        await self._client.disconnect()

    # ─────────────────────── public API ───────────────────────

    def publish(self, event: Any, *, timeout_s: Optional[float] = None) -> bool:
        """Send one signed event; return True when at least one relay OKs it."""

        if not self._running or self._loop is None:
            raise NostrRelayError("relay client is not running")
        timeout = (
            self._publish_timeout
            if timeout_s is None
            else _bounded_timeout(timeout_s, field="timeout_s")
        )
        fut = asyncio.run_coroutine_threadsafe(
            self._client.send_event(event), self._loop
        )
        try:
            output = fut.result(timeout=timeout)
        except asyncio.TimeoutError:
            fut.cancel()
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("nostr publish failed: %s", exc)
            return False
        return self._output_accepted(output)

    def subscribe_events(
        self,
        *,
        kinds: List[int],
        authors: Optional[List[str]] = None,
        namespace: Optional[str] = None,
        callback: Optional[Callable[[Any], None]] = None,
    ) -> None:
        """Subscribe to a kinds filter; events are queued and callback'd."""

        if not self._running or self._loop is None:
            raise NostrRelayError("relay client is not running")
        if (
            not isinstance(kinds, list)
            or not kinds
            or len(kinds) > MAX_SUBSCRIPTION_KINDS
            or any(
                isinstance(kind, bool)
                or not isinstance(kind, int)
                or not 0 <= kind <= 65_535
                for kind in kinds
            )
            or len(set(kinds)) != len(kinds)
        ):
            raise ValueError(
                f"kinds must contain 1..{MAX_SUBSCRIPTION_KINDS} unique integers"
            )
        if authors is not None:
            if (
                not isinstance(authors, list)
                or len(authors) > MAX_SUBSCRIPTION_AUTHORS
                or len(set(authors)) != len(authors)
            ):
                raise ValueError(
                    "authors must be a bounded list without duplicates"
                )
            for author in authors:
                if (
                    not isinstance(author, str)
                    or len(author) != 64
                    or any(character not in "0123456789abcdef" for character in author)
                ):
                    raise ValueError("authors must contain lowercase x-only hex keys")
        if callback is not None and not callable(callback):
            raise TypeError("callback must be callable")
        filter_obj = _Filter().kinds([_Kind(k) for k in kinds])
        if authors:
            filter_obj = filter_obj.authors([_PublicKey.parse(value) for value in authors])
        if namespace is not None:
            if (
                not isinstance(namespace, str)
                or not namespace
                or len(namespace) > 128
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in namespace)
            ):
                raise ValueError("namespace must be 1..128 characters")
            filter_obj = filter_obj.custom_tag(
                _SingleLetterTag.from_byte(ord("t")), namespace
            )
        fut = asyncio.run_coroutine_threadsafe(
            self._subscribe_async(filter_obj, callback), self._loop
        )
        try:
            fut.result(timeout=15.0)
        except asyncio.TimeoutError:
            fut.cancel()
            raise NostrRelayError("nostr subscription timed out after 15s") from None

    async def _subscribe_async(self, filter_obj: Any, callback: Optional[Callable]) -> None:
        from nostr_sdk import ReqTarget as _ReqTarget

        target = _ReqTarget.auto([filter_obj])
        notifications = self._client.notifications()

        previous = self._stream_task
        if previous is not None and not previous.done():
            previous.cancel()
            try:
                await previous
            except asyncio.CancelledError:
                pass
        previous_subscription = self._subscription_id
        if previous_subscription is not None:
            try:
                await self._client.unsubscribe(previous_subscription)
            except Exception as exc:  # noqa: BLE001 - replacing a stale subscription
                logger.debug("nostr unsubscribe before replacement failed: %s", exc)

        output = await self._client.subscribe(target)
        self._subscription_id = output.id

        async def _pump() -> None:
            seen_ids: set[str] = set()
            seen_order: deque[str] = deque()
            try:
                while True:
                    item = await notifications.next()
                    if item is None:
                        break
                    event = self._event_from_notification(item, output.id)
                    if event is None:
                        continue
                    event_id = self._event_id(event)
                    if event_id is not None:
                        if event_id in seen_ids:
                            continue
                        if len(seen_order) >= MAX_SEEN_EVENT_IDS:
                            seen_ids.discard(seen_order.popleft())
                        seen_order.append(event_id)
                        seen_ids.add(event_id)
                    with self._queue_lock:
                        if len(self._queue) == self._queue.maxlen:
                            self._queue.popleft()
                            self._dropped_events += 1
                        self._queue.append(event)
                    if callback is not None:
                        try:
                            callback(event)
                        except Exception:  # noqa: BLE001
                            logger.exception("nostr subscription callback raised")
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - stream errors end the pump
                logger.exception("nostr event stream ended with error")

        self._stream_task = asyncio.create_task(_pump())

    @staticmethod
    def _event_from_notification(item: Any, subscription_id: str) -> Any:
        if isinstance(item, _ns.ClientNotification.MESSAGE):
            relay_message = item.message.as_enum()
            if (
                isinstance(relay_message, _ns.RelayMessageEnum.EVENT_MSG)
                and relay_message.subscription_id == subscription_id
            ):
                return relay_message.event
            return None
        if (
            isinstance(item, _ns.ClientNotification.NEW_EVENT)
            and item.subscription_id == subscription_id
        ):
            return item.event
        return None

    @staticmethod
    def _event_id(event: Any) -> Optional[str]:
        try:
            return event.id().to_hex()
        except (AttributeError, TypeError, ValueError):
            return None

    def poll_events(self, *, max_items: int = 64) -> List[Any]:
        if isinstance(max_items, bool) or not isinstance(max_items, int):
            raise TypeError("max_items must be an integer")
        if max_items <= 0 or max_items > MAX_EVENT_QUEUE:
            raise ValueError(f"max_items must be within [1, {MAX_EVENT_QUEUE}]")
        items: List[Any] = []
        with self._queue_lock:
            while self._queue and len(items) < max_items:
                items.append(self._queue.popleft())
        return items

    @staticmethod
    def _output_accepted(output: Any) -> bool:
        """A publish is accepted when at least one relay sent a truthy OK.

        nostr-sdk 0.45 SendEventOutput: ``success`` is a list of RelayUrl
        that OKed the event, ``failed`` maps rejected relays to reasons."""

        try:
            succeeded = getattr(output, "success", None)
            if isinstance(succeeded, list) and len(succeeded) > 0:
                return True
            return False
        except Exception:  # noqa: BLE001 - introspection must not crash
            return False

    # ─────────────────────── internals ───────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    def queue_depth(self) -> int:
        with self._queue_lock:
            return len(self._queue)

    def dropped_events(self) -> int:
        with self._queue_lock:
            return self._dropped_events


__all__ = [
    "MAX_RELAYS",
    "MAX_SUBSCRIPTION_AUTHORS",
    "MAX_SUBSCRIPTION_KINDS",
    "NostrRelayClient",
    "NostrRelayError",
]
