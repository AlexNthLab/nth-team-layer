"""
Gossip   P2P WebSocket gossip

 Agent  GossipNode WebSocket  agent
-  server client peer
- Agent      peer
- msg_id
-


- WebSocket (RFC 6455) Python asyncio
- websockets extra: pip install nth-dao[p2p]
-  channel.py gossip    channel
- NAT  localhost relay/tunnel

JSON over WebSocket
     {"type": "hello", "agent_id": "...", "pubkey_hex": "..."}
     {"type": "welcome", "agent_id": "...", "channels": [...]}
     {"type": "subscribe", "channel": "team"}
     {"type": "subscribed", "channel": "team"}
     {"type": "gossip", "message": {...ChannelMessage.to_dict()...}}
     {"type": "ack", "msg_id": "..."}
     {"type": "gossip", "message": {...}}  (from other peers)
     {"type": "peer_list"}  (request known peers)
     {"type": "peers", "peers": [{"agent_id": "...", "url": "..."}]}


    node = GossipNode(
        identity=my_identity,
        channel=my_channel,
        host="0.0.0.0",
        port=9876,
    )
    await node.start()

    #  peer
    await node.connect("ws://192.168.1.100:9876")

    #
    await node.subscribe("team")
    await node.subscribe("group:backend")

    #  gossip  peers +  channel
    await node.broadcast("hello team!", scope="team")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger("nth_dao.gossip")

# 重放窗口：超过此秒数的旧消息丢弃（无论签名是否有效）
REPLAY_WINDOW_SECONDS = 600  # 10 分钟
# 时钟漂移容忍：未来 N 秒以内仍接受
FUTURE_DRIFT_SECONDS = 60
# Handshake 挑战超时
HANDSHAKE_TIMEOUT = 8.0

#

_WEBSOCKETS_AVAILABLE = False
try:
    import websockets
    from websockets.asyncio.server import serve
    from websockets.asyncio.client import connect as ws_connect
    _WEBSOCKETS_AVAILABLE = True
except ImportError:
    pass


def _ws_required(feature: str) -> None:
    if not _WEBSOCKETS_AVAILABLE:
        raise ImportError(
            f"{feature} requires websockets. Install with:\n"
            f"  pip install nth-dao[p2p]\n"
            f"  (or: pip install 'websockets>=13.0,<17.0')"
        )


#


@dataclass
class PeerInfo:
    """ peer """
    agent_id: str
    url: str           # ws://host:port
    pubkey_hex: str = ""
    channels: Set[str] = field(default_factory=set)
    connected_at: float = 0.0
    last_seen: float = 0.0

    @property
    def short_id(self) -> str:
        return self.agent_id[:8]


#  GossipNode


class GossipNode:
    """P2P Gossip """

    #
    DEDUP_CACHE_SIZE = 1000
    #
    PING_INTERVAL = 30
    #
    RECONNECT_DELAY = 5
    # 入站 peer 连接数上限(2026-06-14 审查补:网络面 auto/scale 上限)。
    # 防止攻击者(或 TOFU 开启时大量自称不同 agent_id 的连接)无界堆积
    # peer 连接耗资源。可由 NTH_GOSSIP_MAX_PEERS 覆盖;<=0 表示不限。
    MAX_PEERS = 256

    def __init__(
        self,
        identity,       # AgentIdentity (必须带签名能力)
        channel,        # TeamChannel
        host: str = "127.0.0.1",
        port: int = 9876,
        bootstrap_peers: Optional[List[str]] = None,
        trusted_pubkeys: Optional[Dict[str, str]] = None,
        require_signature: bool = True,
        allow_tofu: bool = True,
        trust_graph=None,  # 可选 TrustGraph：启用 web-of-trust 传递信任
        wot_max_depth: int = 2,
        max_peers: Optional[int] = None,  # 入站 peer 上限;None→env/MAX_PEERS
        connect_proxy: "str | bool | None" = True,
    ):
        """
        Args:
            identity: 本节点身份；require_signature=True 时必须能 sign（PyNaCl）
            channel: 本地 channel sink
            host: 监听 host
            port: 监听端口
            bootstrap_peers: 启动时尝试连接的 peer URL
            trusted_pubkeys: 预置的 {agent_id: pubkey_hex}；运行时可用 trust_agent() 追加
            require_signature: True = 拒绝无签名/签名错误的 gossip。默认 True（安全默认）
        """
        _ws_required("GossipNode")
        if require_signature and not (identity and identity.can_sign):
            raise ValueError(
                "GossipNode require_signature=True 需要 identity 能签名 "
                "（AgentIdentity.generate() + pynacl extra）"
            )

        self.identity = identity
        self.channel = channel
        self.host = host
        self.port = port
        self.require_signature = require_signature
        self.allow_tofu = allow_tofu
        if not isinstance(connect_proxy, (str, bool)) and connect_proxy is not None:
            raise ValueError("connect_proxy must be a URL, boolean, or None")
        self.connect_proxy = connect_proxy

        # Peer 连接
        self.peers: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.peer_infos: Dict[str, PeerInfo] = {}
        self.bootstrap_urls = bootstrap_peers or []
        # 入站 peer 上限:None → NTH_GOSSIP_MAX_PEERS / 类常量;<=0 不限。
        if max_peers is None:
            try:
                _mp = int(os.environ.get("NTH_GOSSIP_MAX_PEERS", str(self.MAX_PEERS)))
            except (TypeError, ValueError):
                _mp = self.MAX_PEERS
            self._max_peers = _mp if _mp >= 0 else self.MAX_PEERS
        else:
            self._max_peers = max_peers

        # ───── 信任锚 ─────
        # agent_id → pubkey_hex 的映射，直接 pinned 信任。
        # 不在这里 AND 也不在 trust_graph 可达内的 agent_id → 签名消息被拒（require_signature=True）
        self._trusted_pubkeys: Dict[str, str] = dict(trusted_pubkeys or {})
        # 本节点自己永远在信任里
        if identity and identity.can_sign:
            self._trusted_pubkeys[str(identity.agent_id)] = identity.pubkey_hex
        # 可选 web-of-trust：传递信任图
        self.trust_graph = trust_graph
        self.wot_max_depth = max(1, min(wot_max_depth, 5))
        # 把本地 pinned anchors 也注册成 trust_graph 的 roots（如果有）
        if self.trust_graph is not None:
            for aid, pk in self._trusted_pubkeys.items():
                try:
                    self.trust_graph.add_root(aid, pk)
                except Exception as e:
                    logger.debug("trust_graph.add_root(%s) failed: %s", aid, e)

        # 订阅
        self.subscriptions: Set[str] = set()

        # 去重：msg_id 集合（最近 N 个）
        self._seen: deque = deque(maxlen=self.DEDUP_CACHE_SIZE)
        self._seen_set: Set[str] = set()

        # 回调
        self._on_message: Optional[Callable] = None
        self._on_peer_join: Optional[Callable] = None
        self._on_peer_leave: Optional[Callable] = None

        # 内部状态
        self._server = None
        self._running = False
        self._tasks: List[asyncio.Task] = []

    #

    def _can_accept_peer(self, remote_agent_id: str) -> bool:
        """容量闸:已在册的 agent_id 允许重连(替换旧连接);新 peer 仅在
        未达上限时接纳。<=0 表示不限。抽成独立方法便于单测。"""
        if self._max_peers <= 0:
            return True
        if remote_agent_id in self.peers:
            return True
        return len(self.peers) < self._max_peers

    # ───── 信任锚管理 ─────

    def trust_agent(self, agent_id: str, pubkey_hex: str) -> None:
        """新增/更新一个被信任的 agent_id → pubkey_hex 映射。

        一旦写入，后续来自该 agent_id 的 gossip 都会用此 pubkey 验签。
        切换 pubkey 会断信任链（接下来要 agent 用新 pubkey 重新 handshake）。
        """
        if not agent_id or not pubkey_hex:
            raise ValueError("agent_id and pubkey_hex required")
        old = self._trusted_pubkeys.get(agent_id)
        if old and old != pubkey_hex:
            raise ValueError(f"agent '{agent_id}' is already pinned to a different pubkey")
        self._trusted_pubkeys[agent_id] = pubkey_hex

    def is_trusted(self, agent_id: str) -> bool:
        return agent_id in self._trusted_pubkeys

    def trusted_pubkey_for(self, agent_id: str) -> Optional[str]:
        return self._trusted_pubkeys.get(agent_id)

    # ───── 回调 ─────

    def on_message(self, callback: Callable) -> None:
        """callback(msg_dict, from_agent_id)"""
        self._on_message = callback

    def on_peer_join(self, callback: Callable) -> None:
        """peer callback(peer_info)"""
        self._on_peer_join = callback

    def on_peer_leave(self, callback: Callable) -> None:
        """peer callback(agent_id)"""
        self._on_peer_leave = callback

    #

    async def start(self) -> str:
        """ gossip

        Returns:
             WebSocket URL
        """
        self._running = True
        self._server = await serve(
            self._handle_connection,
            self.host,
            self.port,
        )
        # port=0 时回填 OS 实际分配的端口，让 url 可直接用于 peer 连接
        bound_port = self.port
        if bound_port == 0 and self._server is not None:
            for sock in self._server.sockets:
                bound_port = sock.getsockname()[1]
                break
        url = f"ws://{self.host}:{bound_port}"
        self._bound_url = url

        #  bootstrap peers
        for peer_url in self.bootstrap_urls:
            asyncio.create_task(self._connect_with_retry(peer_url))

        #
        self._tasks.append(asyncio.create_task(self._ping_loop()))

        return url

    async def stop(self) -> None:
        """ gossip """
        self._running = False

        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

        #  peer
        for agent_id, ws in list(self.peers.items()):
            try:
                await ws.close()
            except (OSError, RuntimeError) as e:
                logger.debug("closing peer %s failed: %s", agent_id, e)
        self.peers.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    #

    async def connect(self, url: str) -> bool:
        """主动连接 peer，含 challenge-response 验证对方持有声称的 pubkey。

        Handshake 流程（client 视角）：
            1) → hello {agent_id, pubkey_hex}
            2) ← challenge {nonce}
            3) → challenge_response {nonce_sig}   (用我的私钥签 nonce)
            4) ← welcome {agent_id, pubkey_hex, channels, server_challenge}
            5) → server_challenge_response {server_nonce_sig}
            6) ← ack | close
        """
        _ws_required("connect")
        try:
            # websockets 15+ discovers OS proxies by default. Delivery peers
            # can explicitly disable that without mutating process-global
            # NO_PROXY; older supported versions had no proxy parameter and
            # already connected directly.
            import inspect

            kwargs = {}
            if "proxy" in inspect.signature(ws_connect).parameters:
                kwargs["proxy"] = self.connect_proxy
            ws = await ws_connect(url, **kwargs)
        except Exception as e:
            logger.warning("connect %s failed: %s", url, e)
            return False

        try:
            # 1) hello
            await self._send_hello(ws)

            # 2) 收 challenge
            raw = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT)
            challenge = json.loads(raw)
            if challenge.get("type") != "challenge":
                await ws.close(1008, "expected challenge")
                return False
            nonce = challenge.get("nonce", "")
            if not nonce:
                await ws.close(1008, "missing nonce")
                return False

            # 3) sign challenge
            sig = self.identity.sign_json({"nonce": nonce}).hex() if False else \
                  self.identity.sign(_canon({"nonce": nonce})).hex()
            await self._send_json(ws, {
                "type": "challenge_response",
                "agent_id": str(self.identity.agent_id),
                "sig": sig,
            })

            # 4) 收 welcome（含 server_challenge）
            raw = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT)
            welcome = json.loads(raw)
            if welcome.get("type") != "welcome":
                await ws.close(1008, "expected welcome")
                return False

            remote_agent_id = welcome.get("agent_id", "")
            remote_pubkey = welcome.get("pubkey_hex", "")
            server_nonce = welcome.get("server_challenge", "")
            server_sig = welcome.get("server_sig", "")
            if not (remote_agent_id and remote_pubkey and server_nonce and server_sig):
                await ws.close(1008, "incomplete welcome")
                return False
            known_pubkey = self._trusted_pubkeys.get(remote_agent_id)
            if known_pubkey and known_pubkey != remote_pubkey:
                await ws.close(1008, "pubkey mismatch with trust anchor")
                return False
            if not known_pubkey and not self.allow_tofu:
                await ws.close(1008, "untrusted server")
                return False
            if not _verify_nonce(remote_pubkey, server_nonce, server_sig):
                await ws.close(1008, "invalid server signature")
                return False

            # 5) 我们也签 server_nonce 证身（已经在 step 3 证过，但服务端可能要双签）
            # 这里 server_challenge 已在 _handle_connection 收 challenge_response 时验过；
            # 客户端不需要再回签 server_challenge。welcome 就是 ack。

            # 把对端 pubkey 加入信任锚（首次见 = TOFU；之后 rotate 会 warn）
            if not known_pubkey:
                self.trust_agent(remote_agent_id, remote_pubkey)

            self.peers[remote_agent_id] = ws
            self.peer_infos[remote_agent_id] = PeerInfo(
                agent_id=remote_agent_id,
                url=url,
                pubkey_hex=remote_pubkey,
                channels=set(welcome.get("channels", [])),
                connected_at=time.time(),
                last_seen=time.time(),
            )

            self._tasks.append(asyncio.create_task(self._recv_loop(remote_agent_id, ws)))
            await self._send_json(ws, {"type": "peer_list"})

            if self._on_peer_join:
                try:
                    self._on_peer_join(self.peer_infos[remote_agent_id])
                except Exception:
                    logger.exception("on_peer_join callback raised")
            return True

        except (asyncio.TimeoutError, json.JSONDecodeError, KeyError) as e:
            logger.warning("handshake to %s failed: %s", url, e)
            try:
                await ws.close()
            except Exception:
                pass
            return False
        except Exception as e:
            logger.exception("connect %s unexpected error: %s", url, e)
            try:
                await ws.close()
            except Exception:
                pass
            return False

    async def disconnect(self, agent_id: str) -> None:
        """ peer """
        ws = self.peers.pop(agent_id, None)
        self.peer_infos.pop(agent_id, None)
        if ws:
            try:
                await ws.close()
            except Exception:
                pass
        if self._on_peer_leave:
            self._on_peer_leave(agent_id)

    #

    async def subscribe(self, channel_name: str) -> None:
        """ peer"""
        self.subscriptions.add(channel_name)

        for ws in self.peers.values():
            await self._send_json(ws, {
                "type": "subscribe",
                "channel": channel_name,
            })

    async def unsubscribe(self, channel_name: str) -> None:
        self.subscriptions.discard(channel_name)
        for ws in self.peers.values():
            await self._send_json(ws, {
                "type": "unsubscribe",
                "channel": channel_name,
            })

    #

    async def broadcast(
        self,
        content: str,
        scope: str = "team",
        content_type: str = "text",
        mentions: Optional[List[str]] = None,
        *,
        require_delivery: bool = False,
    ) -> dict:
        """ channel + gossip  peer

        Returns:
             dict
        """
        #  channel
        msg = self.channel.send(
            content=content,
            scope=scope,
            content_type=content_type,
            mentions=mentions,
        )

        msg_dict = msg.to_dict()
        #  seen
        self._seen.append(msg_dict["msg_id"])

        # gossip  peer
        delivered = await self.gossip(msg_dict)
        if require_delivery and delivered == 0:
            raise RuntimeError("no connected peer accepted the gossip message")

        return msg_dict

    async def gossip(self, msg_dict: dict) -> int:
        """ gossip  peer channel"""
        tasks = []
        for ws in self.peers.values():
            tasks.append(self._send_json(ws, {
                "type": "gossip",
                "message": msg_dict,
            }))
        if not tasks:
            return 0
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(not isinstance(outcome, Exception) for outcome in outcomes)

    async def direct_message(
        self,
        to_agent: str,
        content: str,
        content_type: str = "text",
        *,
        relay_if_unknown: bool = True,
    ) -> Optional[dict]:
        """ peer DM channel"""
        msg = self.channel.dm(to_agent, content, content_type)
        msg_dict = msg.to_dict()
        self._seen.append(msg_dict["msg_id"])

        #  peer
        if to_agent in self.peers:
            await self._send_json(self.peers[to_agent], {
                "type": "gossip",
                "message": msg_dict,
            })
            return msg_dict

        if not relay_if_unknown:
            return None
        # peer    peer gossip
        await self.gossip(msg_dict)
        return msg_dict

    #

    def list_peers(self) -> List[PeerInfo]:
        """ peer"""
        return list(self.peer_infos.values())

    def peer_count(self) -> int:
        return len(self.peers)

    @property
    def url(self) -> str:
        # start() 后返回 OS 实际绑定端口的 url（port=0 场景）
        return getattr(self, "_bound_url", f"ws://{self.host}:{self.port}")

    #

    async def _handle_connection(self, ws):
        """服务端 handshake：发 challenge、验证 client 持有 pubkey。"""
        try:
            # 1) 等 hello
            raw = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT)
            hello = json.loads(raw)
            if hello.get("type") != "hello":
                await ws.close(1008, "expected hello")
                return

            remote_agent_id = hello.get("agent_id", "")
            remote_pubkey = hello.get("pubkey_hex", "")
            if not remote_agent_id or not remote_pubkey:
                await ws.close(1008, "missing agent_id/pubkey_hex")
                return

            # 如果是被信任的旧 agent_id，pubkey 必须一致；否则就是冒名
            known_pubkey = self._trusted_pubkeys.get(remote_agent_id)
            if known_pubkey and known_pubkey != remote_pubkey:
                logger.warning(
                    "rejecting connection: %s claims a different pubkey",
                    remote_agent_id,
                )
                await ws.close(1008, "pubkey mismatch with trust anchor")
                return

            # 2) 发 challenge
            if not known_pubkey and not self.allow_tofu:
                await ws.close(1008, "untrusted peer")
                return

            nonce = secrets.token_hex(16)
            await self._send_json(ws, {"type": "challenge", "nonce": nonce})

            # 3) 等 challenge_response，验证签名 = remote 持有 pubkey 对应私钥
            raw = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT)
            resp = json.loads(raw)
            if resp.get("type") != "challenge_response":
                await ws.close(1008, "expected challenge_response")
                return
            client_sig_hex = resp.get("sig", "")
            if not client_sig_hex or not _verify_nonce(remote_pubkey, nonce, client_sig_hex):
                logger.warning(
                    "challenge_response signature invalid for %s", remote_agent_id
                )
                await ws.close(1008, "invalid challenge signature")
                return

            # 容量闸:验签通过后、注册/TOFU 前先查上限。新 peer 超限则拒
            # (1013 = Try Again Later,RFC6455 服务端过载),避免无界堆连接。
            if not self._can_accept_peer(remote_agent_id):
                logger.warning(
                    "rejecting peer %s: at capacity %d/%d",
                    remote_agent_id, len(self.peers), self._max_peers,
                )
                await ws.close(1013, "server at peer capacity")
                return

            # client 通过了 → 把 pubkey 锚定到 agent_id
            if not known_pubkey:
                self.trust_agent(remote_agent_id, remote_pubkey)

            # 4) welcome（也带 server_challenge，可选给 client 验证）
            server_nonce = secrets.token_hex(16)
            server_sig = self.identity.sign(_canon({"nonce": server_nonce})).hex()
            await self._send_json(ws, {
                "type": "welcome",
                "agent_id": str(self.identity.agent_id),
                "pubkey_hex": self.identity.pubkey_hex,
                "channels": list(self.subscriptions),
                "server_challenge": server_nonce,
                "server_sig": server_sig,
            })

            # 注册 peer
            try:
                remote_url = f"ws://{ws.remote_address[0]}:{ws.remote_address[1]}"
            except Exception:
                remote_url = ""
            self.peers[remote_agent_id] = ws
            self.peer_infos[remote_agent_id] = PeerInfo(
                agent_id=remote_agent_id,
                url=remote_url,
                pubkey_hex=remote_pubkey,
                connected_at=time.time(),
                last_seen=time.time(),
            )

            if self._on_peer_join:
                try:
                    self._on_peer_join(self.peer_infos[remote_agent_id])
                except Exception:
                    logger.exception("on_peer_join callback raised")

            # 进入消息循环
            await self._recv_loop(remote_agent_id, ws)

        except asyncio.TimeoutError:
            await ws.close(1008, "handshake timeout")
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("handshake parse error: %s", e)
            try:
                await ws.close(1008, "handshake parse error")
            except Exception:
                pass
        except Exception as e:
            logger.exception("handshake unexpected: %s", e)

    async def _recv_loop(self, agent_id: str, ws):
        """ peer """
        try:
            async for raw in ws:
                # 修复：原代码用 dict.get(.., default) 给 default 对象写 last_seen，
                # 当 peer 不在表里时是 no-op。这里只在存在时更新。
                pi = self.peer_infos.get(agent_id)
                if pi:
                    pi.last_seen = time.time()

                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                msg_type = data.get("type")

                if msg_type == "gossip":
                    await self._handle_gossip(data, agent_id)

                elif msg_type == "peer_list":
                    #  peer
                    peers_list = [
                        {"agent_id": pid, "url": pi.url}
                        for pid, pi in self.peer_infos.items()
                    ]
                    await self._send_json(ws, {
                        "type": "peers",
                        "peers": peers_list,
                    })

                elif msg_type == "peers":
                    #  peer    peer
                    for p in data.get("peers", []):
                        if p["agent_id"] not in self.peers and p["agent_id"] != str(self.identity.agent_id):
                            asyncio.create_task(self._connect_with_retry(p["url"]))

                elif msg_type == "subscribe":
                    ch = data.get("channel", "")
                    if ch:
                        pi = self.peer_infos.get(agent_id)
                        if pi:
                            pi.channels.add(ch)

                elif msg_type == "unsubscribe":
                    ch = data.get("channel", "")
                    pi = self.peer_infos.get(agent_id)
                    if pi and ch in pi.channels:
                        pi.channels.discard(ch)

                elif msg_type == "ping":
                    await self._send_json(ws, {"type": "pong"})

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            # Peer
            await self.disconnect(agent_id)

    async def _handle_gossip(self, data: dict, relay_peer_id: str) -> None:
        """处理从 relay_peer_id 转发来的 gossip 消息。

        安全检查（按顺序）：
            1) msg_id 去重
            2) timestamp 在重放窗口内（防回放）
            3) 用 msg["from_agent"] 对应的 *信任锚 pubkey* 验签
               —— 不是 relay_peer 的 pubkey！gossip 是多跳的
            4) require_signature=True 时，未签名或验签失败 → 拒绝并 log
        """
        msg_dict = data.get("message", {})
        msg_id = msg_dict.get("msg_id", "")
        author_id = msg_dict.get("from_agent", "")
        ts = msg_dict.get("timestamp", "")

        if not msg_id or not author_id:
            logger.debug("dropping gossip without msg_id/from_agent")
            return

        # 1) 去重
        if msg_id in self._seen_set:
            return
        # Mark as seen only after trust and signature checks pass.

        # 2) 时间戳防回放
        if not _within_replay_window(ts):
            logger.warning(
                "dropping replay/skewed msg %s from author=%s ts=%s (relay=%s)",
                msg_id[:8], author_id, ts, relay_peer_id,
            )
            return

        # 3) 用作者的信任锚 pubkey 验签 —— 不是中继者的！
        sig = msg_dict.get("sig", "")
        author_pubkey = self._trusted_pubkeys.get(author_id)
        trust_source = "pinned" if author_pubkey else None

        # 直接锚不命中时，回退到 trust graph 解析（web-of-trust 传递信任）
        if author_pubkey is None and self.trust_graph is not None:
            resolved = self.trust_graph.trusted_pubkey_for(
                author_id, max_depth=self.wot_max_depth,
            )
            if resolved:
                author_pubkey = resolved
                trust_source = "wot"

        if self.require_signature:
            if not sig:
                logger.warning(
                    "dropping unsigned msg %s from %s (relay=%s)",
                    msg_id[:8], author_id, relay_peer_id,
                )
                return
            if not author_pubkey:
                logger.warning(
                    "dropping msg %s from untrusted author=%s "
                    "(no pinned pubkey, no WoT chain within depth=%d)",
                    msg_id[:8], author_id, self.wot_max_depth,
                )
                return
            if not _verify_msg_signature(msg_dict, sig, author_pubkey):
                logger.warning(
                    "dropping msg %s: signature does not match trusted pubkey for %s "
                    "(trust_source=%s)",
                    msg_id[:8], author_id, trust_source,
                )
                return
        else:
            # require_signature=False 模式（仅用于开发/测试）
            if sig and author_pubkey:
                if not _verify_msg_signature(msg_dict, sig, author_pubkey):
                    logger.info(
                        "weak-mode: signature mismatch for %s, accepting anyway",
                        msg_id[:8],
                    )

        # Delivery-layer direct messages carry a signed target marker. They
        # are accepted only by that exact peer and are never relayed onward;
        # otherwise an apparently unicast DID envelope would leak across the
        # gossip mesh on its second hop.
        metadata = msg_dict.get("metadata", {})
        if not isinstance(metadata, dict):
            logger.warning("dropping msg %s with malformed metadata", msg_id[:8])
            return
        direct_to = metadata.get("nth_delivery_direct_to")
        if direct_to is not None:
            if not isinstance(direct_to, str) or direct_to != str(self.identity.agent_id):
                logger.warning(
                    "dropping direct msg %s addressed to another peer", msg_id[:8]
                )
                return

        # 通过 → 入本地 channel ledger
        self._mark_seen(msg_id)
        self._channel_append(msg_dict)

        # 回调
        if self._on_message:
            try:
                self._on_message(msg_dict, relay_peer_id)
            except Exception:
                logger.exception("on_message callback raised")

        # Direct delivery stops at its signed recipient. Public gossip may
        # continue through the mesh.
        if direct_to is None:
            await self._relay(msg_dict, exclude=relay_peer_id)

    async def _relay(self, msg_dict: dict, exclude: str = "") -> None:
        """ peer"""
        tasks = []
        for agent_id, ws in self.peers.items():
            if agent_id != exclude:
                tasks.append(self._send_json(ws, {
                    "type": "gossip",
                    "message": msg_dict,
                }))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _channel_append(self, msg_dict: dict) -> None:
        """ channel"""
        from .channel import ChannelMessage
        msg = ChannelMessage.from_dict(msg_dict)
        self.channel._append(msg)

    def _mark_seen(self, msg_id: str) -> None:
        if len(self._seen) == self._seen.maxlen:
            evicted = self._seen[0]
            self._seen_set.discard(evicted)
        self._seen_set.add(msg_id)
        self._seen.append(msg_id)

    #

    async def _ping_loop(self) -> None:
        """ ping  peer"""
        while self._running:
            await asyncio.sleep(self.PING_INTERVAL)
            for agent_id, ws in list(self.peers.items()):
                try:
                    await self._send_json(ws, {"type": "ping"})
                except Exception:
                    await self.disconnect(agent_id)

    async def _connect_with_retry(self, url: str, max_retries: int = 10) -> None:
        """"""
        for i in range(max_retries):
            if not self._running:
                return
            if await self.connect(url):
                return
            await asyncio.sleep(self.RECONNECT_DELAY * (1 + i * 0.5))

    #

    async def _send_hello(self, ws) -> None:
        await self._send_json(ws, {
            "type": "hello",
            "agent_id": str(self.identity.agent_id),
            "pubkey_hex": self.identity.pubkey_hex,
        })

    @staticmethod
    async def _send_json(ws, data: dict) -> None:
        payload = json.dumps(data, ensure_ascii=False)
        await ws.send(payload)


# ───────────────────── 模块级辅助 ─────────────────────


def _canon(data: dict) -> bytes:
    """canonical JSON bytes —— 跟 identity.canonical_json 保持一致。"""
    from .identity import canonical_json
    return canonical_json(data)


def _verify_nonce(pubkey_hex: str, nonce: str, sig_hex: str) -> bool:
    """验证 challenge nonce 签名 —— 证明 client 持有 pubkey 对应的私钥。"""
    from .identity import _NACL_AVAILABLE, _VerifyKey  # type: ignore
    if not _NACL_AVAILABLE:
        return False
    from nacl.exceptions import BadSignatureError
    try:
        assert _VerifyKey is not None
        verify_key = _VerifyKey(bytes.fromhex(pubkey_hex))
        payload = _canon({"nonce": nonce})
        verify_key.verify(payload, bytes.fromhex(sig_hex))
        return True
    except (AssertionError, BadSignatureError, TypeError, ValueError):
        return False


def _verify_msg_signature(msg_dict: dict, sig_hex: str, pubkey_hex: str) -> bool:
    """验证 ChannelMessage 的签名 —— 必须用作者的 pubkey，不是中继者的。"""
    from .identity import _NACL_AVAILABLE, _VerifyKey  # type: ignore
    if not _NACL_AVAILABLE:
        return False
    from nacl.exceptions import BadSignatureError
    # 与 channel.TeamChannel.send() 中签名时构造 payload 的字段对齐
    payload = {
        "msg_id": msg_dict.get("msg_id", ""),
        "channel": msg_dict.get("channel", ""),
        "from_agent": msg_dict.get("from_agent", ""),
        "content": msg_dict.get("content", ""),
        "content_type": msg_dict.get("content_type", "text"),
        "reply_to": msg_dict.get("reply_to", ""),
        "mentions": msg_dict.get("mentions", []),
        "timestamp": msg_dict.get("timestamp", ""),
        "metadata": msg_dict.get("metadata", {}),
    }
    try:
        assert _VerifyKey is not None
        _VerifyKey(bytes.fromhex(pubkey_hex)).verify(
            _canon(payload), bytes.fromhex(sig_hex)
        )
        return True
    except (AssertionError, BadSignatureError, TypeError, ValueError):
        return False


def _within_replay_window(ts: str) -> bool:
    """timestamp 在 [now - REPLAY_WINDOW, now + FUTURE_DRIFT] 之内？"""
    if not ts:
        return False
    try:
        msg_time = datetime.fromisoformat(ts)
    except ValueError:
        return False
    now = datetime.now()
    delta = (now - msg_time).total_seconds()
    if delta > REPLAY_WINDOW_SECONDS:
        return False
    if delta < -FUTURE_DRIFT_SECONDS:
        return False
    return True
