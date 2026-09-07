"""In-process fake Nostr relay speaking the NIP-01 wire protocol.

Used to test the relay client and NostrTransport without a real relay
network. Runs a websockets server (same borrowed library as the gossip
adapter) on a loopback port:

* ``["EVENT", ev]``   → verify id/sig via nostr-sdk, store, reply
  ``["OK", id, true, ""]`` (or ``false`` with reason on tamper)
* ``["REQ", sub, filter_json]`` → send matching stored events then
  ``["EOSE", sub]``
* ``["CLOSE", sub]``  → drop the subscription

Filters are matched on ``kind``, author, and tag selectors — enough for the
delivery-layer tests, deliberately not a full NIP-01 filter engine.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Dict, List, Optional, Set

import nostr_sdk as _ns


class FakeNostrRelay:
    """One in-process NIP-01 relay. Start/stop are thread-safe."""

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        import websockets  # borrowed: p2p/nostr extra

        self._websockets = websockets
        self._host = host
        self._port = port
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._events: List[dict] = []       # stored events (json dicts)
        self._seen_event_ids: Set[str] = set()
        # NIP-01 subscription identifiers are scoped to one relay connection.
        # Different clients routinely choose the same identifier.
        self._subscriptions: Dict[Any, Dict[str, dict]] = {}
        self._reject_next = False           # hostile-relay test switch
        self._connections: Set[Any] = set()

    # ─────────────────────── lifecycle ───────────────────────

    def start(self) -> str:
        if self._running:
            return self.url

        async def _serve() -> None:
            self._server = await self._websockets.serve(
                self._handle_connection, self._host, self._port
            )
            self._running = True

        loop = asyncio.new_event_loop()
        self._loop = loop
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        future = asyncio.run_coroutine_threadsafe(_serve(), loop)
        future.result(timeout=10.0)
        host, port = self._server.sockets[0].getsockname()[:2]
        shown = "127.0.0.1" if host in {"0.0.0.0", "::"} else str(host)
        return f"ws://{shown}:{port}"

    def _run_loop(self) -> None:
        loop = self._loop
        assert loop is not None
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            loop.close()

    def stop(self) -> None:
        if self._server is not None:
            closer = asyncio.run_coroutine_threadsafe(self._server.wait_closed() if False else self._close_async(), self._loop)
            closer.result(timeout=5.0)
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._running = False

    async def _close_async(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def url(self) -> str:
        host, port = self._server.sockets[0].getsockname()[:2]
        shown = "127.0.0.1" if host in {"0.0.0.0", "::"} else str(host)
        return f"ws://{shown}:{port}"

    # ─────────────────────── test controls ───────────────────────

    def stored_events(self) -> List[dict]:
        with self._lock:
            return list(self._events)

    def set_reject_next(self, value: bool) -> None:
        """When True, the next EVENT gets OK=false (hostile relay probe)."""

        self._reject_next = value

    # ─────────────────────── wire handling ───────────────────────

    async def _handle_connection(self, websocket: Any) -> None:
        with self._lock:
            self._connections.add(websocket)
        try:
            async for raw in websocket:
                try:
                    message = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if not isinstance(message, list) or not message:
                    continue
                command = message[0]
                if command == "EVENT" and len(message) >= 2:
                    await self._handle_event(websocket, message[1])
                elif command == "REQ" and len(message) >= 3:
                    await self._handle_req(websocket, message[1], message[2])
                elif command == "CLOSE" and len(message) >= 2:
                    with self._lock:
                        subscriptions = self._subscriptions.get(websocket)
                        if subscriptions is not None:
                            subscriptions.pop(message[1], None)
        except Exception:  # noqa: BLE001 - connection errors end the handler
            pass
        finally:
            with self._lock:
                self._connections.discard(websocket)
                self._subscriptions.pop(websocket, None)

    async def _handle_event(self, websocket: Any, event: dict) -> None:
        event_id = event.get("id", "")
        with self._lock:
            reject = self._reject_next
        if reject:
            await websocket.send(json.dumps(["OK", event_id, False, "rejected by relay"]))
            return
        # verify the event signature through the borrowed nostr-sdk
        try:
            parsed = _ns.Event.from_json(json.dumps(event))
            if not parsed.verify_signature():
                await websocket.send(json.dumps(["OK", event_id, False, "bad signature"]))
                return
        except Exception:
            await websocket.send(json.dumps(["OK", event_id, False, "invalid event"]))
            return
        with self._lock:
            if event_id not in self._seen_event_ids:
                self._events.append(event)
                self._seen_event_ids.add(event_id)
            subscribers = [
                (connection, sub_id, filter_json)
                for connection, subscriptions in self._subscriptions.items()
                for sub_id, filter_json in subscriptions.items()
            ]
        await websocket.send(json.dumps(["OK", event_id, True, ""]))
        # fan out to matching subscriptions
        for connection, sub_id, filter_json in subscribers:
            if self._matches(filter_json, event):
                try:
                    await connection.send(json.dumps(["EVENT", sub_id, event]))
                except Exception:  # noqa: BLE001 - peer may disconnect mid-fanout
                    pass

    async def _handle_req(self, websocket: Any, sub_id: str, filter_json: dict) -> None:
        with self._lock:
            self._subscriptions.setdefault(websocket, {})[sub_id] = filter_json
            matching = [e for e in self._events if self._matches(filter_json, e)]
        for event in matching:
            await websocket.send(json.dumps(["EVENT", sub_id, event]))
        await websocket.send(json.dumps(["EOSE", sub_id]))

    @staticmethod
    def _matches(filter_json: dict, event: dict) -> bool:
        kinds = filter_json.get("kinds")
        if kinds and event.get("kind") not in kinds:
            return False
        authors = filter_json.get("authors")
        if authors and event.get("pubkey") not in authors:
            return False
        d_tag_values = filter_json.get("#d")
        if d_tag_values is not None:
            tags = event.get("tags", [])
            event_d = next(
                (tag[1] for tag in tags if isinstance(tag, list) and tag and tag[0] == "d"),
                None,
            )
            if event_d not in d_tag_values:
                return False
        for key, expected_values in filter_json.items():
            if not key.startswith("#") or key == "#d":
                continue
            tag_name = key[1:]
            tags = event.get("tags", [])
            actual_values = {
                tag[1]
                for tag in tags
                if isinstance(tag, list) and len(tag) >= 2 and tag[0] == tag_name
            }
            if not actual_values.intersection(expected_values):
                return False
        return True
