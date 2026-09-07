"""Unified local web console for NTH DAO.

The web layer is intentionally thin: it exposes the existing local-first
membership and group APIs without bypassing their permission checks.
"""

from __future__ import annotations

from collections import OrderedDict
from contextlib import asynccontextmanager
import hashlib
import ipaddress
import logging
import os
import hmac
import json
import re
import secrets
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, List, Optional, TYPE_CHECKING, Union
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from nth_dao.a2a_card import (
    A2A_SPEC_VERSION as _A2A_SPEC_VERSION,
    build_a2a_card as _build_a2a_card,
    known_skills as _known_a2a_skills,
    sign_a2a_card_jws as _sign_a2a_card_jws,
)
from nth_dao.a2a_rpc import A2ARPCHandler, TaskStore as _A2ATaskStore
from nth_dao.agent_code import code_for_agent_id, code_for_pubkey, parse_code
from nth_dao.cap_token import (
    AUTH_SCHEME_CAP_TOKEN,
    CapTokenStore as _CapTokenStore,
    DEFAULT_TTL_MS as _CAP_DEFAULT_TTL_MS,
    KNOWN_CAPABILITIES as _CAP_KNOWN,
    decode_authorization_value as _decode_cap_auth,
    encode_authorization_header as _encode_cap_auth,
    sign_cap_token as _sign_cap_token,
    verify_cap_token as _verify_cap_token,
)
from nth_dao.contact_book import SOURCE_MANUAL as CONTACT_SOURCE_MANUAL
from nth_dao.execution_receipt import ReceiptStore as _ReceiptStore
# R-58 (2026-06-08): hoist did_key helpers to module scope so
# `_resolve_member_identity` doesn't re-execute the import statement
# inside the search hot loop. sys.modules already caches the module,
# but a stable top-level binding eliminates the per-call frame setup.
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.discovery import (
    AgentRegistry,
    LANDiscovery,
    PeerFinder,
    configured_discovery_port,
)
from nth_dao.groups import DEFAULT_CHANNEL_ID, GroupManager, TaskStatus
from nth_dao.group_registry import (
    GroupPolicy,
    GroupRegistry,
    GroupRegistryError,
    PolicyChangeProposal,
    resolve_proposal,
)
from nth_dao.identity import AgentID
from nth_dao.mandate import (
    KIND_CART,
    KIND_INTENT,
    KIND_PAYMENT,
    KINDS as MANDATE_KINDS,
    MandateStore,
    cart_mandate_digest,
    cart_satisfies_intent,
    complete_triad_chain,
    intent_mandate_digest,
    is_cart_expired,
    is_intent_expired,
    is_payment_expired,
    payment_mandate_digest,
    verify_cart_mandate,
    verify_intent_mandate,
    verify_payment_mandate,
)
from nth_dao.membership import MembershipManager, TeamConfig, TeamRole
from nth_dao.orchestration import MissionStore
from nth_dao.plugins import (
    InvocationAuthority,
    PluginAuditError,
    PluginAuthorizationError,
    PluginDependencyError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
    PluginLifecycleError,
    PluginSchemaError,
)
from nth_dao.web.rate_limit import (
    PersistentRateLimiter,
    RateLimiter,
    enforce_min_response_time,
)
from team_layer.blackboard import Blackboard

if TYPE_CHECKING:
    from nth_dao.contact_book import ContactRecord

logger = logging.getLogger("nth_dao.web")


_FOREIGN_CLAIM_MAX_BODY_BYTES = 256 * 1024
_FEDERATION_HELLO_MAX_BODY_BYTES = 16 * 1024
_COMMERCE_CART_MAX_BODY_BYTES = 256 * 1024
_COMMERCE_SYNC_MAX_BODY_BYTES = 768 * 1024
_COMMERCE_WRITE_MAX_BODY_BYTES = 768 * 1024
_TRADE_OFFER_MAX_BODY_BYTES = 256 * 1024
_TRADE_RECOGNITION_MAX_BODY_BYTES = 256 * 1024
_TRADE_RECOGNITION_POLICY_MAX_BODY_BYTES = 256 * 1024
_TRADE_PROPOSAL_DELIVERY_MAX_BODY_BYTES = 256 * 1024
_TRADE_ORDER_DELIVERY_MAX_BODY_BYTES = 256 * 1024
_TRADE_EXECUTION_RECEIPT_DELIVERY_MAX_BODY_BYTES = 2 * 1024 * 1024
_TRADE_EXECUTION_RECEIPT_DISPATCH_MAX_BODY_BYTES = 16 * 1024
_TRADE_RECEIPT_REVIEW_DELIVERY_MAX_BODY_BYTES = 2 * 1024 * 1024
_TRADE_RECEIPT_REVIEW_WRITE_MAX_BODY_BYTES = 32 * 1024
_TRADE_DISPUTE_STATEMENT_DELIVERY_MAX_BODY_BYTES = 512 * 1024
_TRADE_DISPUTE_STATEMENT_WRITE_MAX_BODY_BYTES = 256 * 1024
_TRADE_DISPUTE_STATEMENT_FETCH_MAX_BODY_BYTES = 16 * 1024
_TRADE_DISPUTE_BOOT_RECOVERY_BATCH = 100
_TRADE_DISPUTE_BOOT_RECOVERY_MAX_PASSES = 5
_RESOURCE_PROFILE_MAX_BODY_BYTES = 256 * 1024
_TRADE_ORDER_BOOT_RECOVERY_BATCH = 1_000
_TRADE_ORDER_BOOT_RECOVERY_MAX_PASSES = 5
_TRADE_EXECUTION_RECOVERY_POLL_SECONDS = 30.0
_TRADE_DISPUTE_RECOVERY_POLL_SECONDS = 30.0
_TRADE_DISPUTE_URGENT_MAX_TARGETS = 256
_TRADE_DISPUTE_URGENT_MAX_ATTEMPTS = 5
_TRADE_DISPUTE_URGENT_BASE_BACKOFF_SECONDS = 0.05
_TRADE_DISPUTE_STATEMENT_DELIVERY_PATH = re.compile(
    r"/api/v2/trade/federation/orders/"
    r"sha256:[0-9a-f]{64}/execution-receipts/"
    r"nth-trade-execution-sha256:[0-9a-f]{64}/reviews/"
    r"nth-trade-review-sha256:[0-9a-f]{64}/dispute-statements"
)
_TRADE_DISPUTE_STATEMENT_WRITE_PATH = re.compile(
    r"/api/v2/trade/orders/"
    r"sha256:[0-9a-f]{64}/execution-receipts/"
    r"nth-trade-execution-sha256:[0-9a-f]{64}/reviews/"
    r"nth-trade-review-sha256:[0-9a-f]{64}/dispute-statements"
    r"(?:/sha256:[0-9a-f]{64}/deliver)?"
)
_TRADE_DISPUTE_STATEMENT_FETCH_FEDERATION_PATH = re.compile(
    r"/api/v2/trade/federation/orders/"
    r"sha256:[0-9a-f]{64}/execution-receipts/"
    r"nth-trade-execution-sha256:[0-9a-f]{64}/reviews/"
    r"nth-trade-review-sha256:[0-9a-f]{64}/dispute-statements/fetch"
)
_TRADE_DISPUTE_STATEMENT_FETCH_WRITE_PATH = re.compile(
    r"/api/v2/trade/orders/"
    r"sha256:[0-9a-f]{64}/execution-receipts/"
    r"nth-trade-execution-sha256:[0-9a-f]{64}/reviews/"
    r"nth-trade-review-sha256:[0-9a-f]{64}/dispute-statements/fetch"
)


class _RequestBodyTooLarge(Exception):
    pass


class _FederationBodyLimitMiddleware:
    """Bound anonymous federation writes before FastAPI buffers JSON."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        path = str(scope.get("path") or "")
        is_foreign_claim = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path.startswith("/api/v2/market/")
            and path.endswith("/claim-foreign")
        )
        is_federation_hello = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path == "/api/v2/market/federation/hello"
        )
        is_commerce_cart = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path == "/api/v2/commerce/carts"
        )
        is_commerce_sync = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path == "/api/v2/commerce/federation/sync"
        )
        is_commerce_write = (
            scope.get("type") == "http"
            and scope.get("method") in {"POST", "PUT", "PATCH"}
            and path.startswith("/api/v2/commerce/")
        )
        is_trade_offer_write = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path == "/api/v2/trade/offers"
        )
        is_trade_recognition_write = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path.startswith("/api/v2/trade/rule-packages/")
            and (
                path.endswith("/recognitions")
                or path.endswith("/recognitions/reconcile")
            )
        )
        is_trade_recognition_import_repair = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path.startswith("/api/v2/trade/orders/")
            and path.endswith("/recognitions/imports/repair")
        )
        is_trade_recognition_policy_write = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path in {
                "/api/v2/trade/recognition-policy",
                "/api/v2/trade/recognition-policy/reconcile",
            }
        )
        is_trade_proposal_delivery = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path == "/api/v2/trade/federation/proposals"
        )
        is_trade_order_delivery = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path == "/api/v2/trade/federation/orders"
        )
        is_trade_execution_receipt_delivery = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and re.fullmatch(
                r"/api/v2/trade/federation/orders/"
                r"sha256:[0-9a-f]{64}/execution-receipts",
                path,
            )
            is not None
        )
        is_trade_execution_receipt_dispatch = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and re.fullmatch(
                r"/api/v2/trade/orders/sha256:[0-9a-f]{64}/"
                r"execution-receipts/[^/]+/deliver",
                path,
            )
            is not None
        )
        is_trade_receipt_review_delivery = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and re.fullmatch(
                r"/api/v2/trade/federation/orders/"
                r"sha256:[0-9a-f]{64}/execution-receipts/[^/]+/reviews",
                path,
            )
            is not None
        )
        is_trade_dispute_statement_delivery = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and _TRADE_DISPUTE_STATEMENT_DELIVERY_PATH.fullmatch(path) is not None
        )
        is_trade_dispute_statement_fetch = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and (
                _TRADE_DISPUTE_STATEMENT_FETCH_FEDERATION_PATH.fullmatch(path)
                is not None
                or _TRADE_DISPUTE_STATEMENT_FETCH_WRITE_PATH.fullmatch(path) is not None
            )
        )
        is_trade_dispute_statement_write = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and _TRADE_DISPUTE_STATEMENT_WRITE_PATH.fullmatch(path) is not None
        )
        is_trade_receipt_review_write = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and re.fullmatch(
                r"/api/v2/trade/orders/sha256:[0-9a-f]{64}/"
                r"execution-receipts/[^/]+/reviews(?:/[^/]+/deliver)?",
                path,
            )
            is not None
        )
        is_trade_proposal_accept = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path.startswith("/api/v2/trade/proposals/")
            and path.endswith("/accept")
        )
        is_resource_profile_write = (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and path.startswith("/api/v2/market/resource-profiles/")
        )
        if not (
            is_foreign_claim
            or is_federation_hello
            or is_commerce_write
            or is_trade_offer_write
            or is_trade_recognition_write
            or is_trade_recognition_import_repair
            or is_trade_recognition_policy_write
            or is_trade_proposal_delivery
            or is_trade_order_delivery
            or is_trade_execution_receipt_delivery
            or is_trade_execution_receipt_dispatch
            or is_trade_receipt_review_delivery
            or is_trade_dispute_statement_delivery
            or is_trade_dispute_statement_fetch
            or is_trade_dispute_statement_write
            or is_trade_receipt_review_write
            or is_trade_proposal_accept
            or is_resource_profile_write
        ):
            await self.app(scope, receive, send)
            return

        if is_foreign_claim:
            max_body_bytes = _FOREIGN_CLAIM_MAX_BODY_BYTES
            body_label = "foreign claim"
        elif is_federation_hello:
            max_body_bytes = _FEDERATION_HELLO_MAX_BODY_BYTES
            body_label = "federation hello"
        elif is_commerce_cart:
            max_body_bytes = _COMMERCE_CART_MAX_BODY_BYTES
            body_label = "commerce cart"
        elif is_commerce_sync:
            max_body_bytes = _COMMERCE_SYNC_MAX_BODY_BYTES
            body_label = "commerce sync"
        elif is_trade_offer_write:
            max_body_bytes = _TRADE_OFFER_MAX_BODY_BYTES
            body_label = "trade offer"
        elif is_trade_recognition_write or is_trade_recognition_import_repair:
            max_body_bytes = _TRADE_RECOGNITION_MAX_BODY_BYTES
            body_label = "trade rule recognition"
        elif is_trade_recognition_policy_write:
            max_body_bytes = _TRADE_RECOGNITION_POLICY_MAX_BODY_BYTES
            body_label = "trade rule recognition policy"
        elif is_trade_proposal_delivery:
            max_body_bytes = _TRADE_PROPOSAL_DELIVERY_MAX_BODY_BYTES
            body_label = "trade Proposal delivery"
        elif is_trade_order_delivery:
            max_body_bytes = _TRADE_ORDER_DELIVERY_MAX_BODY_BYTES
            body_label = "trade Order delivery"
        elif is_trade_execution_receipt_delivery:
            max_body_bytes = _TRADE_EXECUTION_RECEIPT_DELIVERY_MAX_BODY_BYTES
            body_label = "trade Execution Receipt delivery"
        elif is_trade_execution_receipt_dispatch:
            max_body_bytes = _TRADE_EXECUTION_RECEIPT_DISPATCH_MAX_BODY_BYTES
            body_label = "trade Execution Receipt dispatch"
        elif is_trade_receipt_review_delivery:
            max_body_bytes = _TRADE_RECEIPT_REVIEW_DELIVERY_MAX_BODY_BYTES
            body_label = "trade Receipt Review delivery"
        elif is_trade_dispute_statement_delivery:
            max_body_bytes = _TRADE_DISPUTE_STATEMENT_DELIVERY_MAX_BODY_BYTES
            body_label = "trade Dispute Statement delivery"
        elif is_trade_dispute_statement_fetch:
            max_body_bytes = _TRADE_DISPUTE_STATEMENT_FETCH_MAX_BODY_BYTES
            body_label = "trade Dispute Statement fetch"
        elif is_trade_dispute_statement_write:
            max_body_bytes = _TRADE_DISPUTE_STATEMENT_WRITE_MAX_BODY_BYTES
            body_label = "trade Dispute Statement write"
        elif is_trade_receipt_review_write:
            max_body_bytes = _TRADE_RECEIPT_REVIEW_WRITE_MAX_BODY_BYTES
            body_label = "trade Receipt Review write"
        elif is_trade_proposal_accept:
            max_body_bytes = _TRADE_PROPOSAL_DELIVERY_MAX_BODY_BYTES
            body_label = "trade Proposal acceptance"
        elif is_resource_profile_write:
            max_body_bytes = _RESOURCE_PROFILE_MAX_BODY_BYTES
            body_label = "Resource Profile"
        else:
            max_body_bytes = _COMMERCE_WRITE_MAX_BODY_BYTES
            body_label = "commerce write"
        limit_label = f"{max_body_bytes // 1024} KiB"
        lengths: List[int] = []
        for name, value in scope.get("headers") or []:
            if name.lower() != b"content-length":
                continue
            try:
                parsed = int(value.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Content-Length must be a non-negative integer"},
                )
                await response(scope, receive, send)
                return
            if parsed < 0:
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Content-Length must be a non-negative integer"},
                )
                await response(scope, receive, send)
                return
            lengths.append(parsed)
        if len(set(lengths)) > 1:
            response = JSONResponse(
                status_code=400,
                content={"detail": "conflicting Content-Length headers"},
            )
            await response(scope, receive, send)
            return
        if lengths and lengths[0] > max_body_bytes:
            response = JSONResponse(
                status_code=413,
                content={"detail": f"{body_label} body exceeds {limit_label}"},
            )
            await response(scope, receive, send)
            return

        received = 0

        async def limited_receive() -> dict:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body") or b"")
                if received > max_body_bytes:
                    raise _RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestBodyTooLarge:
            response = JSONResponse(
                status_code=413,
                content={"detail": f"{body_label} body exceeds {limit_label}"},
            )
            await response(scope, receive, send)

DEFAULT_ADMIN_ID = "admin"
STATIC_DIR = Path(__file__).resolve().parent / "static"
CONSOLE_TOKEN_ENV = "NTH_CONSOLE_TOKEN"
CONSOLE_TOKEN_DIR_ENV = "NTH_CONSOLE_TOKEN_DIR"
CONSOLE_TOKEN_FILENAME = "console.token"
# 公网部署设为 0/false:页面不再内嵌全权 console token(否则"任何拿到 URL 的人
# GET / 即得全权 token")。默认 1(本地便利:浏览器加载即自带令牌)。
CONSOLE_TOKEN_IN_PAGE_ENV = "NTH_CONSOLE_TOKEN_IN_PAGE"

# Week-1 Task 5: capture the process boot time once at import so the
# /api/build_id endpoint can report it. Used by the dashboard top bar
# to detect "JS bundle newer than backend process" drift.
_BACKEND_STARTED_AT = (
    __import__("datetime").datetime.now().isoformat()
)


def _compute_git_rev_at_startup() -> str:
    """Architect audit R-2: capture git rev exactly once at import.

    Previously /api/build_id spawned ``git`` on every request - a
    trivial DoS amplifier and an unbounded fork-rate problem under
    load. The rev cannot change for a running process, so we
    compute once. Best-effort: returns "unknown" if anything goes
    wrong, never raises.
    """
    import subprocess as _sp

    candidate_cwds = [
        Path(__file__).resolve().parent.parent.parent,    # source checkout
        Path.cwd(),                                       # fallback
    ]
    for cwd in candidate_cwds:
        try:
            rev = _sp.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=str(cwd),
                capture_output=True, text=True, timeout=2.0,
            )
            if rev.returncode == 0 and rev.stdout.strip():
                return rev.stdout.strip()
        except (_sp.TimeoutExpired, OSError, FileNotFoundError):
            continue
    return "unknown"


_BACKEND_GIT_REV: str = _compute_git_rev_at_startup()


def _resolve_safe_workspace(
    workspace: Optional[Union[str, Path]],
) -> Path:
    """R-23 (2026-06-08): pick a workspace path that will NOT leak the
    Ed25519 private key into a committed git tree.

    Precedence:

      1. Explicit ``workspace`` argument (caller knows what they want;
         we still warn if it sits inside a git tree, but defer to
         them - this keeps tests with tmp_path frictionless).
      2. ``NTH_WORKSPACE`` env var (operator override; same warn-only
         posture).
      3. Default: ``~/.nth-dao/workspaces/default/``. Crucially NOT
         ``Path.cwd()`` - that almost certainly IS a git tree when
         the dev runs ``python -m nth_dao.web`` from the project
         root, which is the exact path by which the private key
         landed in the source tree on the prior incident.

    A workspace under a git checkout is functional (we don't refuse
    to start), but we emit a single loud WARNING with the specific
    paths that would be at risk. The operator can either move the
    workspace or tighten their .gitignore.
    """
    if workspace is not None:
        root = Path(workspace).resolve()
    elif os.environ.get("NTH_WORKSPACE", "").strip():
        root = Path(os.environ["NTH_WORKSPACE"]).resolve()
    else:
        # Safe default - NOT cwd.
        root = (
            Path.home() / ".nth-dao" / "workspaces" / "default"
        ).resolve()
        root.mkdir(parents=True, exist_ok=True)
    _warn_if_workspace_inside_git_tree(root)
    return root


def _warn_if_workspace_inside_git_tree(root: Path) -> None:
    """Look upward for a ``.git`` directory. If found, emit one
    WARNING per process so the operator knows their identity material
    sits inside a checkout where a careless ``git add -A`` could
    stage the private key.

    We deliberately don't refuse to start - users absolutely need to
    be able to point a workspace at a custom dir, including ones
    inside a development checkout. But silence here is what got us
    into trouble the first time.
    """
    for parent in [root, *root.parents]:
        if (parent / ".git").exists():
            logger.warning(
                "NTH DAO workspace %s sits inside a git checkout at %s. "
                "The workspace WILL persist your Ed25519 private key "
                "(<workspace>/.nth/identity.json), team.json, and "
                "contact book. Ensure your .gitignore excludes "
                "these paths (NTH DAO ships rules for this; verify "
                "with `git check-ignore -v <workspace>/.nth/identity.json`) "
                "OR move the workspace outside the checkout by setting "
                "NTH_WORKSPACE.",
                root, parent,
            )
            return


# Architect R-5: module-level limiter (NOT per-state) so a noisy actor
# can't bypass by reconnecting; the cap is global across the process.
# 5 LAN broadcasts per actor per minute is plenty for legitimate use
# (operator clicking Refresh) and reduces amplification potential to a
# negligible level.
_lan_discover_limiter = RateLimiter(max_per_window=5, window_seconds=60.0)


def _local_lan_ip() -> str:
    """Best-effort LAN address for opt-in federation advertisements."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def _clean_public_base_url(raw: str) -> str:
    value = str(raw or "").strip().rstrip("/")
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
    except Exception:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")).rstrip("/")


def _configured_public_base_url() -> str:
    """Return an explicitly configured or safely derivable HTTP base URL.

    Cross-machine federation needs a URL another node can dial. We never
    infer that from loopback, because advertising ``http://127.0.0.1`` over
    mDNS would point every peer back to itself.
    """
    for name in (
        "NTH_PUBLIC_BASE_URL",
        "NTH_FEDERATION_BASE_URL",
        "NTH_LAN_BASE_URL",
    ):
        cleaned = _clean_public_base_url(os.environ.get(name, ""))
        if cleaned:
            return cleaned

    host = os.environ.get("NTH_HOST", "127.0.0.1").strip() or "127.0.0.1"
    if host in {"127.0.0.1", "::1", "localhost"}:
        return ""
    if os.environ.get("NTH_ALLOW_REMOTE_BIND", "").strip() != "1":
        return ""
    port = os.environ.get("NTH_PORT", "8080").strip() or "8080"
    if host in {"0.0.0.0", "::"}:
        host = _local_lan_ip()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return _clean_public_base_url(f"http://{host}:{port}")


def _federation_directory(base_url: str) -> dict[str, Any]:
    base = _clean_public_base_url(base_url)
    if not base:
        return {"protocol": "nth-dao-federation-v1", "enabled": False}
    return {
        "protocol": "nth-dao-federation-v1",
        "enabled": True,
        "peer_url": base,
        "market": {
            "open_url": f"{base}/api/v2/market/open",
            "digest_url": f"{base}/api/v2/market/federation/digest",
            "pull_url": f"{base}/api/v2/market/federation/pull",
            "peers_url": f"{base}/api/v2/market/federation/peers",
            "claim_foreign_url": f"{base}/api/v2/market/federation/claim-foreign",
            "claim_foreign_legacy_url": (
                f"{base}/api/v2/market/{{announcement_id}}/claim-foreign"
            ),
        },
        "social": {
            "pull_url": f"{base}/api/v2/social/federation/pull",
        },
    }


def _console_token_path() -> Path:
    """Return the operator-local console token path.

    The token is deliberately not stored in the repo/workspace tree:
    workspaces are meant to be synced, forked, and published. The console
    token is an operator secret and therefore lives in the user's home
    configuration directory unless tests override it.
    """
    configured = os.environ.get(CONSOLE_TOKEN_DIR_ENV, "").strip()
    if configured:
        return Path(configured).expanduser() / CONSOLE_TOKEN_FILENAME
    return Path.home() / ".nth-dao" / CONSOLE_TOKEN_FILENAME


def _load_or_create_console_token() -> str:
    """Load or create the Bearer token used by the local web console."""
    env_token = os.environ.get(CONSOLE_TOKEN_ENV, "").strip()
    if env_token:
        return env_token

    path = _console_token_path()
    try:
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("could not read console token %s: %s", path, exc)

    token = secrets.token_urlsafe(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(token + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            logger.debug("could not chmod console token %s", path)
    except OSError as exc:
        logger.warning(
            "could not persist console token %s; using process-local token: %s",
            path, exc,
        )
    return token


def _extract_bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    prefix = "Bearer "
    if not auth.startswith(prefix):
        return ""
    return auth[len(prefix):].strip()


def _extract_cap_token_auth(request: Request) -> str:
    """Return the raw value following ``Authorization: CapToken `` or
    empty if the header doesn't use the cap-token scheme.

    L1-3 (2026-06-08): the CapToken scheme is distinct from Bearer so
    a single ``Authorization`` header can carry only ONE auth flavour
    at a time — no ambiguity for the middleware deciding which path
    the request takes.
    """
    auth = request.headers.get("authorization", "")
    prefix = AUTH_SCHEME_CAP_TOKEN + " "
    if not auth.startswith(prefix):
        return ""
    return auth[len(prefix):].strip()


def get_request_principal(request: Request) -> dict:
    """Return the auth-resolved principal attached to ``request.state``.

    Possible shapes:
        {"type": "console"}                    — full operator access
        {"type": "cap_token", "token": <dict>} — delegated, scoped
        {"type": "anonymous"}                  — no auth supplied
                                                 (only present when
                                                 require_console_auth
                                                 is off)

    Endpoint handlers that want to enforce capability-level access
    should call ``_require_capability(request, "<cap-string>",
    task_id=…)`` rather than introspecting this directly.
    """
    return getattr(request.state, "nth_principal", {"type": "anonymous"})


class _MtimeCache:
    """Architect R-4 (2026-06-07): generic mtime-keyed cache.

    Before this layer the search endpoint walked the full WoT JSONL
    AND globbed every group file on every request. The dashboard
    polls every 5 seconds, so under N concurrent operators that
    quadratic-disk problem only gets worse.

    The contract: ``get(probe_paths, compute)`` invokes ``compute()``
    only when any of ``probe_paths`` changed mtime since the last
    successful call; otherwise returns the cached value. Designed
    for read-mostly file-backed data structures (WoT, group
    registry) where on-disk state is the source of truth and
    invalidations happen via filesystem writes we already do.
    """

    def __init__(self) -> None:
        self._cached_value: Any = None
        self._cached_signature: Optional[tuple] = None

    def get(
        self,
        probe_paths: List[Path],
        compute: "Callable[[], Any]",
    ) -> Any:
        signature: List[tuple] = []
        for p in probe_paths:
            try:
                st = p.stat()
                signature.append((str(p), st.st_mtime_ns, st.st_size))
            except (OSError, FileNotFoundError):
                signature.append((str(p), 0, 0))
        sig_tuple = tuple(signature)
        if sig_tuple == self._cached_signature:
            return self._cached_value
        value = compute()
        self._cached_value = value
        self._cached_signature = sig_tuple
        return value
    def invalidate(self) -> None:
        """Force the next get() call to recompute. Useful in tests."""
        self._cached_value = None
        self._cached_signature = None

class WebState:
    def __init__(self, workspace: Path):
        from nth_dao.web.market_federation_poll import FederationCache

        self.workspace = workspace
        self.market_fed_cache = FederationCache()
        self.plugin_host = PluginHost(
            policy=PluginHostPolicy(
                allowed_permissions=frozenset(
                    {
                        "filesystem.read.workspace",
                        "filesystem.write.workspace",
                        "network.client",
                    }
                ),
                max_risk_tier=3,
            ),
            workspace_root=workspace,
        )
        self.plugin_lifecycle_lock = threading.RLock()
        self.curated_registry_refresh_lock = threading.Lock()
        self.curated_registry_refresh_limiter = RateLimiter(
            max_per_window=6,
            window_seconds=60.0,
            max_tracked_keys=128,
        )
        self.membership = MembershipManager(workspace)
        self.groups = GroupManager(workspace, membership=self.membership)
        self.registry = AgentRegistry(str(workspace / "team_agents"))
        self.missions = MissionStore(str(workspace / "missions"))
        self.blackboard = Blackboard(workspace / "blackboard")
        # v0.9.6: cross-workspace-unique group registry + governance
        self.group_registry = GroupRegistry(workspace)
        self.peer_finder = PeerFinder(self.registry)
        # Week-1 Task 4: lazy-loaded TrustGraph for endorsement counts.
        # Lives on disk under ``team_trust/``; reading on every search
        # request is cheap (filesystem cache + small append-only JSONL).
        from ..web_of_trust import TrustGraph

        self.trust = TrustGraph(workspace)
        # DID persistence (2026-06-08): the workspace's contact book.
        # /api/agents/add writes here so a peer's DID survives a process
        # restart, and /api/agents/search reads here to enrich home rows.
        from ..contact_book import ContactBook
        self.contacts = ContactBook(workspace)
        # DID bootstrap (2026-06-07): this node's permanent Ed25519
        # identity. Populated by ``_bootstrap`` after ``load_or_generate``
        # writes / reads ``<workspace>/identity/identity.json``. May be
        # None on first boot if PyNaCl is missing or the workspace is
        # read-only - in that case all DID-emitting endpoints degrade
        # to "did": "" rather than raising.
        self.node_identity: Optional[Any] = None
        # Spine(Phase 2b 接线):本 workspace 的统一签名因果日志,**单例**——
        # 写入者用内存链头 + 锁,必须全进程共享一个;每请求新建会让并发 append
        # 读到同一链头、各自写同 seq → 分叉。由 _bootstrap 在 node_identity 就绪后
        # 建;node_identity 缺失 / 日志损坏时降级为 None(market 等回退到只写自身
        # feed,不影子双写)。
        self.spine: Optional[Any] = None
        # Mission execution evidence (2026-07-02): lazy EventBus singleton.
        # v2 mission mutations emit signed audit events here and link them to
        # team_receipts entries. It stays lazy so bootstrap can survive broken
        # audit directories; mutation endpoints degrade with warnings instead.
        self.event_bus: Optional[Any] = None
        # LAN DID publish (2026-06-07): the running mDNS responder, or
        # None when ``NTH_LAN_PUBLISH=0`` / zeroconf is missing / startup
        # failed. Closed by ``_register_shutdown_hooks`` on process exit
        # so we don't leak a stale advertisement on the LAN.
        self.mdns_responder: Optional[Any] = None
        # Stdlib UDP discovery is the fallback when mDNS/Bonjour is missing
        # or blocked. It is started only in explicit LAN mode and its unsigned
        # hint is always followed by signed identity-card verification.
        self.lan_udp_responder: Optional[Any] = None
        # Architect R-4 (2026-06-07): mtime-keyed caches for the two
        # hot-path file scans the search endpoint used to do per request.
        # Both invalidate automatically the next time the underlying
        # file changes its mtime (which the safe_append_jsonl /
        # GroupRegistry.publish call paths already trigger via
        # atomic_write / fsync).
        self._endorsement_count_cache = _MtimeCache()
        self._group_list_cache = _MtimeCache()
        # v0.10 T-9: Mandate triad file-backed store, sidebar reads from this
        self.mandates = MandateStore(workspace)
        # No-real-money commerce MVP stores. Order views are derived from the
        # verified Order + Trade chains; the outbox is the only mutable
        # delivery bookkeeping and can be safely retried after restart.
        from ..commerce import (
            ListingStore,
            OrderStore,
            ProvisionalImportStore,
            TradeStore,
        )
        from ..commerce.outbox import CommerceInbox, CommerceOutbox
        self.commerce_listings = ListingStore(workspace)
        self.commerce_orders = OrderStore(workspace)
        self.commerce_trades = TradeStore(workspace)
        self.commerce_provisional = ProvisionalImportStore(workspace)
        self.commerce_outbox = CommerceOutbox(workspace)
        self.commerce_inbox = CommerceInbox(workspace)
        self.commerce_cart_limiter = PersistentRateLimiter(
            Path(workspace) / "commerce" / "rate_limits" / "cart.json",
            max_per_window=120,
            window_seconds=60.0,
        )
        self.commerce_sync_limiter = PersistentRateLimiter(
            Path(workspace) / "commerce" / "rate_limits" / "sync.json",
            max_per_window=300,
            window_seconds=60.0,
        )
        # Trade Offer v2 is intentionally separate from the legacy, rigid
        # Commerce v1 listing model. The append-only store retains signed
        # revisions and conflicts for local projection and later federation.
        from ..trade_rules import (
            OfferStore,
            RulePackageStore,
            TradeExecutionRuntimeHealth,
            RuleRecognitionStore,
            TradeExecutionAuditOutbox,
            TradeExecutionReceiptStore,
            TradeExecutionReceiptDispatchStore,
            TradeDisputeStatementIntakeJournal,
            TradeDisputeStatementIntakeJournalError,
            TradeDisputeStatementFetchJournal,
            TradeDisputeStatementFetchJournalError,
            TradeDisputeStatementFetchOutbox,
            TradeDisputeStatementFetchOutboxError,
            TradeDisputeStatementDispatchError,
            TradeDisputeStatementDispatchStore,
            TradeDisputeStatementStore,
            TradeReceiptReviewDispatchStore,
            TradeReceiptReviewStore,
            TradeOrderAuditOutbox,
            TradeOrderDispatchStore,
            TradeOrderStore,
        )

        self.trade_offers = OfferStore(workspace)
        self.trade_rule_packages = RulePackageStore(workspace)
        self.trade_rule_recognitions = RuleRecognitionStore(workspace)
        self.trade_execution_receipts = TradeExecutionReceiptStore(workspace)
        self.trade_execution_audit_outbox = TradeExecutionAuditOutbox(workspace)
        self.trade_execution_coordinator: Optional[Any] = None
        self.trade_execution_dispatch_store = (
            TradeExecutionReceiptDispatchStore(workspace)
        )
        self.trade_execution_dispatch: Optional[Any] = None
        self.trade_receipt_reviews = TradeReceiptReviewStore(workspace)
        self.trade_receipt_review_coordinator: Optional[Any] = None
        self.trade_receipt_review_dispatch_store = (
            TradeReceiptReviewDispatchStore(workspace)
        )
        self.trade_receipt_review_dispatch: Optional[Any] = None
        self.trade_dispute_statements = TradeDisputeStatementStore(workspace)
        self.trade_dispute_statement_audit: Optional[Any] = None
        try:
            self.trade_dispute_statement_dispatch_store = (
                TradeDisputeStatementDispatchStore(workspace)
            )
        except (OSError, TradeDisputeStatementDispatchError) as exc:
            logger.warning(
                "trade Dispute Statement dispatch store unavailable (%s); "
                "outbound Statement delivery disabled until repaired",
                type(exc).__name__,
            )
            self.trade_dispute_statement_dispatch_store = None
        self.trade_dispute_statement_dispatch: Optional[Any] = None
        self.trade_dispute_statement_recovery_worker: Optional[Any] = None
        self.trade_dispute_statement_projection_lock = threading.RLock()
        self.trade_dispute_statement_projection_token: Optional[Any] = None
        self.trade_dispute_statement_projection_events: tuple[Any, ...] = ()
        self.trade_dispute_statement_recovery_lock = threading.Lock()
        try:
            self.trade_dispute_statement_intake_journal = (
                TradeDisputeStatementIntakeJournal(workspace)
            )
        except (OSError, TradeDisputeStatementIntakeJournalError) as exc:
            logger.warning(
                "trade Dispute Statement intake journal unavailable (%s); "
                "federated Statement intake disabled until repaired",
                type(exc).__name__,
            )
            self.trade_dispute_statement_intake_journal = None
        try:
            self.trade_dispute_statement_fetch_journal = (
                TradeDisputeStatementFetchJournal(workspace)
            )
        except (OSError, TradeDisputeStatementFetchJournalError) as exc:
            logger.warning(
                "trade Dispute Statement fetch journal unavailable (%s); "
                "federated Statement fetch disabled until repaired",
                type(exc).__name__,
            )
            self.trade_dispute_statement_fetch_journal = None
        try:
            self.trade_dispute_statement_fetch_outbox = (
                TradeDisputeStatementFetchOutbox(workspace)
            )
        except (OSError, TradeDisputeStatementFetchOutboxError) as exc:
            logger.warning(
                "trade Dispute Statement fetch outbox unavailable (%s); "
                "outbound Statement fetch disabled until repaired",
                type(exc).__name__,
            )
            self.trade_dispute_statement_fetch_outbox = None
        self.trade_dispute_statement_fetch_coordinator_lock = threading.RLock()
        self.trade_dispute_statement_fetch_coordinators: OrderedDict[
            str,
            Any,
        ] = OrderedDict()
        self.trade_dispute_statement_fetch_max_coordinators = 8
        self.trade_dispute_statement_fetch_coordinator_ttl_seconds = 300.0
        self.trade_dispute_statement_fetch_cache_bytes_per_coordinator = 2 * 1024 * 1024
        self.trade_execution_health_lock = threading.RLock()
        self.trade_execution_recovery_lock = threading.Lock()
        self.trade_execution_recovery_cursor: Optional[str] = None
        self.trade_execution_recovery_failures = 0
        self.trade_execution_health = TradeExecutionRuntimeHealth(
            status="unavailable",
            receipt_persistence_available=False,
            error_code="coordinator-not-initialized",
        )
        # Execution trust is deliberately not inferred from bilateral signed
        # Agreement policy. Deployments must inject a current local policy and
        # exact content-addressed Adapter/content resolvers explicitly.
        self.trade_executor_policy: Optional[Any] = None
        self.trade_execution_adapter_resolver: Optional[Any] = None
        self.trade_execution_adapter_policy: Optional[Any] = None
        self.trade_execution_content_resolver: Optional[Any] = None
        self.trade_execution_schema_validator: Optional[Any] = None
        self.trade_execution_receipt_delivery_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "execution_receipt_delivery.json",
            max_per_window=30,
            window_seconds=60.0,
        )
        self.trade_execution_receipt_delivery_global_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "execution_receipt_delivery_global.json",
            max_per_window=120,
            window_seconds=60.0,
            max_tracked_keys=4,
        )
        self.trade_receipt_review_delivery_limiter = PersistentRateLimiter(
            Path(workspace) / "trade" / "rate_limits" / "receipt_review_delivery.json",
            max_per_window=30,
            window_seconds=60.0,
        )
        self.trade_receipt_review_delivery_global_limiter = (
            PersistentRateLimiter(
                Path(workspace)
                / "trade"
                / "rate_limits"
                / "receipt_review_delivery_global.json",
                max_per_window=120,
                window_seconds=60.0,
                max_tracked_keys=4,
            )
        )
        self.trade_dispute_statement_delivery_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "dispute_statement_delivery.json",
            max_per_window=30,
            window_seconds=60.0,
        )
        self.trade_dispute_statement_delivery_global_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "dispute_statement_delivery_global.json",
            max_per_window=120,
            window_seconds=60.0,
            max_tracked_keys=4,
        )
        self.trade_dispute_statement_fetch_limiter = PersistentRateLimiter(
            Path(workspace) / "trade" / "rate_limits" / "dispute_statement_fetch.json",
            max_per_window=30, window_seconds=60.0,
        )
        self.trade_dispute_statement_fetch_global_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "dispute_statement_fetch_global.json",
            max_per_window=120,
            window_seconds=60.0,
            max_tracked_keys=4,
        )
        self.trade_order_store = TradeOrderStore(workspace)
        self.trade_order_audit_outbox = TradeOrderAuditOutbox(workspace)
        self.trade_order_dispatch_store = TradeOrderDispatchStore(workspace)
        self.trade_order_audit: Optional[Any] = None
        self.trade_order_intake: Optional[Any] = None
        self.trade_order_dispatch: Optional[Any] = None
        self.trade_order_delivery_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "order_delivery.json",
            max_per_window=30,
            window_seconds=60.0,
        )
        self.trade_order_delivery_global_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "order_delivery_global.json",
            max_per_window=120,
            window_seconds=60.0,
            max_tracked_keys=4,
        )
        self.trade_proposal_inbox: Optional[Any] = None
        self.trade_proposal_audit: Optional[Any] = None
        self.trade_proposal_delivery_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "proposal_delivery.json",
            max_per_window=30,
            window_seconds=60.0,
        )
        self.trade_proposal_delivery_global_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "proposal_delivery_global.json",
            max_per_window=120,
            window_seconds=60.0,
            max_tracked_keys=4,
        )
        self.trade_rule_recognition_audit: Optional[Any] = None
        self.trade_rule_recognition_policy_store: Optional[Any] = None
        self.trade_rule_recognition_policy_audit: Optional[Any] = None
        self.trade_rule_recognition_policy_limiter = PersistentRateLimiter(
            Path(workspace)
            / "trade"
            / "rate_limits"
            / "recognition_policy.json",
            max_per_window=30,
            window_seconds=60.0,
        )
        # v0.10 V-30: per-actor rate limiters for the two crypto-heavy
        # /api/mandates/* routes. The verify endpoint is more sensitive
        # (free oracle + timing side-channel) so its window is tighter.
        # Defaults sized for a sidebar in active use: ~30 verify calls
        # per minute is plenty for clicking through a panel of rows.
        self.verify_limiter = RateLimiter(
            max_per_window=30,
            window_seconds=60.0,
        )
        self.store_limiter = RateLimiter(
            max_per_window=60, window_seconds=60.0,
        )
        # L1-1 (2026-06-08): signed execution receipts (motebit
        # execution-ledger@1.0 compatible). Lives under
        # <workspace>/team_receipts/.
        self.receipts = _ReceiptStore(workspace)
        # L1-2 (2026-06-08): A2A Protocol task store. In-memory only
        # for v1 — the receipt is the persistent work-proof; the task
        # itself is ephemeral and re-derivable from receipts if we
        # ever need restart-survival.
        self.a2a_tasks = _A2ATaskStore()
        # L1-3 (2026-06-08): capability delegation tokens — audit
        # store + revocation list. Lives under
        # <workspace>/team_cap_tokens/.
        self.cap_tokens = _CapTokenStore(workspace)

# L1-3 (2026-06-08): cap-token request payloads. Defined at module
# scope rather than inside ``create_app`` because Pydantic forward-
# reference resolution doesn't always work for BaseModel subclasses
# declared inside a closure (FastAPI then treats the param as a
# query string, which is wrong for a JSON body).
class IssueCapTokenPayload(BaseModel):
    subject_did: str
    capabilities: List[str]
    scope_task_id: str = ""
    scope_dao: str = ""
    # Phase 6b: per-token model scope. See ``sign_cap_token``
    # docstring for the None / [] / [...] semantics.
    scope_model_allowlist: Optional[List[str]] = None
    ttl_ms: int = _CAP_DEFAULT_TTL_MS
    token_id: str = ""


class RevokeCapTokenPayload(BaseModel):
    token_id: str


class PluginActionPayload(BaseModel):
    actor_id: str = Field(min_length=1, max_length=256)


class CuratedRegistryRefreshPayload(PluginActionPayload):
    limit: int = Field(default=32, ge=1, le=64)


class JoinPayload(BaseModel):
    agent_id: str
    token: str = ""


class ChannelPayload(BaseModel):
    actor_id: str
    name: str
    topic: str = ""
    channel_id: str = ""
    is_private: bool = False
    member_ids: list[str] = []


class MessagePayload(BaseModel):
    agent_id: str
    body: str
    channel_id: str = DEFAULT_CHANNEL_ID


class AnnouncementPayload(BaseModel):
    author_id: str
    title: str
    body: str
    channel_id: str = DEFAULT_CHANNEL_ID


class TaskPayload(BaseModel):
    created_by: str
    title: str
    description: str = ""
    assignee_id: str = ""
    channel_id: str = DEFAULT_CHANNEL_ID
    due_at: str = ""


class TaskStatusPayload(BaseModel):
    actor_id: str
    status: str
    note: str = ""


# v0.9.6: add-friend / search / discover / group-governance payloads


class AddAgentPayload(BaseModel):
    """Friend-request style direct add. Resolves an agent_id OR a did:key."""

    actor_id: str
    target_agent_id: str = ""
    target_did: str = ""
    label: str = ""


class GroupCreatePayload(BaseModel):
    actor_id: str
    actor_pubkey_hex: str           # signing pubkey of the founder
    display_name: str
    description: str = ""
    policy: str = "open"            # open | approval | closed | voted


class GroupSearchPayload(BaseModel):
    query: str
    limit: int = 10
    policy: Optional[str] = None


class PolicyProposalPayload(BaseModel):
    actor_pubkey_hex: str
    group_id: str
    new_policy: Optional[str] = None
    add_member_pubkeys: list[str] = []
    remove_member_pubkeys: list[str] = []
    new_display_name: Optional[str] = None
    rationale: str = ""
    ttl_days: int = 7


class VoteCastPayload(BaseModel):
    voter_pubkey_hex: str
    proposal_id: str
    choice: str = "yes"   # yes / no / abstain


class LANDiscoverPayload(BaseModel):
    # Architect R-5 (2026-06-07): actor_id is now REQUIRED so the
    # endpoint shares the same member-gate as the rest of the console.
    # Pre-fix anyone reachable could fire an unbounded UDP broadcast
    # through us, and could probe PSK values by varying the request.
    actor_id: str = ""
    timeout_seconds: float = 2.0
    # ``psk`` is intentionally NOT taken from the request body anymore.
    # The server pulls it from ``NTH_DISCOVERY_PSK`` (or stays empty),
    # so untrusted clients cannot probe acceptable PSK values one at
    # a time.
    wanted_capabilities: list[str] = []


class GroupPublishPayload(BaseModel):
    record: dict[str, Any]


class ProposalPublishPayload(BaseModel):
    proposal: dict[str, Any]


class SignedVotePayload(BaseModel):
    vote: dict[str, Any]


# v0.10 T-9: Mandate sidebar


class MandateStorePayload(BaseModel):
    """Persist a signed mandate body into the workspace store.

    The sidebar issues this after the browser wallet has signed an
    IntentMandate; settlement adapters issue this after receiving carts
    or completing payments. Server determines digest from the body so
    callers cannot forge an inconsistent index entry.

    Voss V-28: ``actor_id`` is required so the request goes through
    the same membership gate as the rest of the web console.
    """

    kind: str                    # "intent" | "cart" | "payment"
    mandate: dict[str, Any]
    actor_id: str


class MandateVerifyPayload(BaseModel):
    """Verify a mandate's Ed25519 signature against its canonical JSON.

    For carts, optionally bind-check against an intent by passing
    ``against_intent``. For payments, ``against_intent`` and
    ``against_cart`` are both required because a PaymentMandate is only
    authorizing inside the full Intent -> Cart -> Payment triad.

    Voss V-28: ``actor_id`` required for membership gating.
    """

    kind: str                    # "intent" | "cart" | "payment"
    mandate: dict[str, Any]
    against_intent: Optional[dict[str, Any]] = None
    against_cart: Optional[dict[str, Any]] = None
    actor_id: str


def _advance_trade_execution_recovery_locked(
    state: WebState,
    *,
    limit: int = _TRADE_ORDER_BOOT_RECOVERY_BATCH,
) -> Any:
    """Advance one bounded page of pending Receipt audit recovery."""

    from ..trade_rules import (
        TradeExecutionAuditBusy,
        TradeExecutionRuntimeHealth,
    )

    coordinator = state.trade_execution_coordinator
    if coordinator is None:
        raise RuntimeError("trade execution coordinator is unavailable")
    with state.trade_execution_health_lock:
        cursor = state.trade_execution_recovery_cursor
        prior_failures = state.trade_execution_recovery_failures
        current_health = state.trade_execution_health
        state.trade_execution_health = TradeExecutionRuntimeHealth(
            status="recovering",
            receipt_persistence_available=(
                current_health.receipt_persistence_available
                if isinstance(current_health, TradeExecutionRuntimeHealth)
                else False
            ),
            recovery_pending=True,
            error_code="runtime-recovery",
        )
    try:
        report = coordinator.reconcile(
            limit=limit,
            after_execution_id=cursor,
            pending_only=True,
        )
    except TradeExecutionAuditBusy:
        with state.trade_execution_health_lock:
            current_health = state.trade_execution_health
            state.trade_execution_health = TradeExecutionRuntimeHealth(
                status="recovering",
                receipt_persistence_available=(
                    current_health.receipt_persistence_available
                ),
                recovery_pending=True,
                error_code="runtime-recovery-busy",
            )
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        with state.trade_execution_health_lock:
            state.trade_execution_health = TradeExecutionRuntimeHealth(
                status="degraded",
                receipt_persistence_available=False,
                recovery_pending=True,
                error_code="runtime-recovery-failed",
            )
        raise

    cycle_failures = prior_failures + report.failed
    with state.trade_execution_health_lock:
        if report.has_more:
            if not report.next_cursor:
                state.trade_execution_health = TradeExecutionRuntimeHealth(
                    status="degraded",
                    receipt_persistence_available=False,
                    recovery_pending=True,
                    error_code="runtime-recovery-invalid-cursor",
                )
                raise RuntimeError("execution recovery omitted its next cursor")
            state.trade_execution_recovery_cursor = report.next_cursor
            state.trade_execution_recovery_failures = cycle_failures
            state.trade_execution_health = TradeExecutionRuntimeHealth(
                status=("degraded" if cycle_failures else "recovering"),
                receipt_persistence_available=True,
                recovery_pending=True,
                error_code=(
                    "recovery-record-failures"
                    if cycle_failures
                    else "recovery-pending"
                ),
            )
        else:
            state.trade_execution_recovery_cursor = None
            state.trade_execution_recovery_failures = 0
            state.trade_execution_health = TradeExecutionRuntimeHealth(
                status=("degraded" if cycle_failures else "healthy"),
                receipt_persistence_available=True,
                recovery_pending=bool(cycle_failures),
                error_code=(
                    "recovery-record-failures" if cycle_failures else ""
                ),
            )
    return report


def _advance_trade_execution_recovery(
    state: WebState,
    *,
    limit: int = _TRADE_ORDER_BOOT_RECOVERY_BATCH,
) -> Any:
    """Serialize one recovery page across worker and operator requests."""

    from ..trade_rules import TradeExecutionAuditBusy

    lock = getattr(state, "trade_execution_recovery_lock", None)
    if lock is None or not lock.acquire(blocking=False):
        raise TradeExecutionAuditBusy(
            "execution audit recovery cycle is already running"
        )
    try:
        return _advance_trade_execution_recovery_locked(state, limit=limit)
    finally:
        lock.release()


def _recover_trade_dispute_statement_audits(state: WebState) -> dict[str, Any]:
    """Replay one bounded set of prepare-before-publish audit records."""

    lock = getattr(state, "trade_dispute_statement_recovery_lock", None)
    if lock is None or not lock.acquire(blocking=False):
        raise RuntimeError("Dispute Statement audit recovery is already running")
    try:
        coordinator = state.trade_dispute_statement_audit
        if state.spine is None or coordinator is None:
            raise RuntimeError("Dispute Statement audit recovery is unavailable")
        report = {
            "scanned": 0,
            "anchored": 0,
            "verified_anchored": 0,
            "failed": 0,
            "has_more": False,
        }
        cursor: str | None = None
        for _pass in range(_TRADE_DISPUTE_BOOT_RECOVERY_MAX_PASSES):
            page = coordinator.reconcile(
                package_resolver=state.trade_rule_packages,
                limit=_TRADE_DISPUTE_BOOT_RECOVERY_BATCH,
                after_digest=cursor,
            )
            report["scanned"] += page.scanned
            report["anchored"] += page.anchored
            report["verified_anchored"] += page.verified_anchored
            report["failed"] += page.failed
            report["has_more"] = page.has_more
            if not page.has_more:
                break
            if not page.next_cursor or page.next_cursor == cursor:
                raise RuntimeError(
                    "Dispute Statement recovery returned an invalid cursor"
                )
            cursor = page.next_cursor
        return report
    finally:
        lock.release()


def _recover_trade_dispute_statement_dispatch_acknowledgements(
    state: WebState,
) -> dict[str, Any]:
    """Replay one bounded set of verified remote ACK Spine anchors."""

    lock = getattr(state, "trade_dispute_statement_recovery_lock", None)
    if lock is None or not lock.acquire(blocking=False):
        raise RuntimeError(
            "Dispute Statement acknowledgement recovery is already running"
        )
    try:
        coordinator = state.trade_dispute_statement_dispatch
        if state.spine is None or coordinator is None:
            raise RuntimeError(
                "Dispute Statement acknowledgement recovery is unavailable"
            )
        report = {
            "scanned": 0,
            "anchored": 0,
            "failed": 0,
            "has_more": False,
        }
        cursor: str | None = None
        for _pass in range(_TRADE_DISPUTE_BOOT_RECOVERY_MAX_PASSES):
            page = coordinator.reconcile(
                limit=_TRADE_DISPUTE_BOOT_RECOVERY_BATCH,
                after_digest=cursor,
            )
            report["scanned"] += page.scanned
            report["anchored"] += page.anchored
            report["failed"] += page.failed
            report["has_more"] = page.has_more
            if not page.has_more:
                break
            if not page.next_cursor or page.next_cursor == cursor:
                raise RuntimeError(
                    "Dispute Statement acknowledgement recovery returned an "
                    "invalid cursor"
                )
            cursor = page.next_cursor
        return report
    finally:
        lock.release()


def _recover_trade_dispute_statement_dispatch_acknowledgement(
    state: WebState,
    statement_digest: str,
) -> bool:
    """Recover one retained ACK without scanning unrelated statements."""

    if re.fullmatch(r"sha256:[0-9a-f]{64}", statement_digest) is None:
        raise ValueError("Dispute Statement digest is invalid")
    lock = getattr(state, "trade_dispute_statement_recovery_lock", None)
    if lock is None or not lock.acquire(blocking=False):
        raise RuntimeError(
            "Dispute Statement acknowledgement recovery is already running"
        )
    try:
        coordinator = state.trade_dispute_statement_dispatch
        if state.spine is None or coordinator is None:
            raise RuntimeError(
                "Dispute Statement acknowledgement recovery is unavailable"
            )
        record = coordinator.recover_acknowledgement(statement_digest)
        return bool(record is not None and record.anchor_event_id)
    finally:
        lock.release()


class _TradeExecutionRecoveryWorker:
    """Lifecycle-owned recovery for crash-interrupted Receipt audit writes."""

    def __init__(self, state: WebState) -> None:
        self._state = state
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._state.trade_execution_coordinator is None:
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._cancel.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="nth-trade-execution-recovery",
                daemon=True,
            )
            thread = self._thread
        thread.start()

    def stop(self) -> None:
        self._cancel.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def _run(self) -> None:
        try:
            while not self._cancel.is_set():
                try:
                    report = _advance_trade_execution_recovery(self._state)
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    logger.warning(
                        "trade execution audit background recovery failed (%s)",
                        type(exc).__name__,
                    )
                    self._cancel.wait(_TRADE_EXECUTION_RECOVERY_POLL_SECONDS)
                    continue
                if report.has_more:
                    continue
                self._cancel.wait(_TRADE_EXECUTION_RECOVERY_POLL_SECONDS)
        finally:
            with self._lock:
                self._thread = None


class _TradeDisputeStatementRecoveryWorker:
    """Lifecycle-owned repair for retained claims missing a Spine anchor."""

    def __init__(self, state: WebState) -> None:
        self._state = state
        self._cancel = threading.Event()
        self._wake_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._urgent_targets: OrderedDict[str, dict[str, float | int]] = OrderedDict()

    def start(self) -> None:
        if (
            self._state.trade_dispute_statement_audit is None
            and self._state.trade_dispute_statement_dispatch is None
        ):
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._cancel.clear()
            self._wake_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="nth-trade-dispute-audit-recovery",
                daemon=True,
            )
            thread = self._thread
        thread.start()

    def stop(self) -> None:
        self._cancel.set()
        self._wake_event.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def wake(
        self,
        statement_digest: str | None = None,
        *,
        urgent_for_s: float = 0.0,
    ) -> bool:
        """Interrupt idle wait and optionally queue one exact ACK recovery."""

        if (
            isinstance(urgent_for_s, bool)
            or not isinstance(urgent_for_s, (int, float))
            or not 0.0 <= float(urgent_for_s) <= 30.0
        ):
            raise ValueError("urgent_for_s must be between zero and 30 seconds")
        if statement_digest is not None and re.fullmatch(
            r"sha256:[0-9a-f]{64}", statement_digest
        ) is None:
            raise ValueError("statement_digest is invalid")
        queued = False
        if statement_digest is not None:
            now = time.monotonic()
            with self._lock:
                existing = self._urgent_targets.get(statement_digest)
                if existing is None and len(self._urgent_targets) >= (
                    _TRADE_DISPUTE_URGENT_MAX_TARGETS
                ):
                    return False
                expires_at = now + max(float(urgent_for_s), 1.0)
                if existing is None:
                    self._urgent_targets[statement_digest] = {
                        "attempts": 0,
                        "next_at": now,
                        "expires_at": expires_at,
                    }
                queued = True
        self._wake_event.set()
        return queued

    def _take_due_target(self) -> tuple[str, dict[str, float | int]] | None:
        now = time.monotonic()
        with self._lock:
            for digest in tuple(self._urgent_targets):
                item = self._urgent_targets[digest]
                if (
                    now >= float(item["expires_at"])
                    or int(item["attempts"]) >= _TRADE_DISPUTE_URGENT_MAX_ATTEMPTS
                ):
                    self._urgent_targets.pop(digest, None)
                    continue
                if now >= float(item["next_at"]):
                    return digest, self._urgent_targets.pop(digest)
        return None

    def _retry_target(
        self,
        statement_digest: str,
        item: dict[str, float | int],
    ) -> None:
        attempts = int(item["attempts"]) + 1
        now = time.monotonic()
        if (
            attempts >= _TRADE_DISPUTE_URGENT_MAX_ATTEMPTS
            or now >= float(item["expires_at"])
        ):
            return
        item["attempts"] = attempts
        item["next_at"] = now + min(
            _TRADE_DISPUTE_URGENT_BASE_BACKOFF_SECONDS * (2 ** (attempts - 1)),
            1.0,
        )
        with self._lock:
            newer = self._urgent_targets.get(statement_digest)
            if newer is None:
                self._urgent_targets[statement_digest] = item
            else:
                newer["attempts"] = max(
                    int(newer["attempts"]),
                    attempts,
                )
                newer["next_at"] = max(
                    float(newer["next_at"]),
                    float(item["next_at"]),
                )
                newer["expires_at"] = min(
                    float(newer["expires_at"]),
                    float(item["expires_at"]),
                )

    def _next_wait_seconds(self) -> float:
        with self._lock:
            next_times = [float(item["next_at"]) for item in self._urgent_targets.values()]
        if not next_times:
            return _TRADE_DISPUTE_RECOVERY_POLL_SECONDS
        return max(
            0.0,
            min(
                _TRADE_DISPUTE_RECOVERY_POLL_SECONDS,
                min(next_times) - time.monotonic(),
            ),
        )

    def _run(self) -> None:
        try:
            while not self._cancel.is_set():
                target = self._take_due_target()
                if target is not None:
                    statement_digest, target_state = target
                    try:
                        recovered = (
                            _recover_trade_dispute_statement_dispatch_acknowledgement(
                                self._state,
                                statement_digest,
                            )
                        )
                    except (OSError, RuntimeError, TypeError, ValueError) as exc:
                        logger.warning(
                            "targeted trade Dispute Statement acknowledgement "
                            "recovery failed for %s (%s)",
                            statement_digest,
                            type(exc).__name__,
                        )
                        recovered = False
                    if not recovered:
                        self._retry_target(statement_digest, target_state)
                    continue
                has_more = False
                try:
                    report = _recover_trade_dispute_statement_audits(
                        self._state
                    )
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    logger.warning(
                        "trade Dispute Statement audit background recovery failed (%s)",
                        type(exc).__name__,
                    )
                    report = {"has_more": False, "failed": 1}
                has_more = has_more or report["has_more"]
                try:
                    dispatch_report = (
                        _recover_trade_dispute_statement_dispatch_acknowledgements(
                            self._state
                        )
                    )
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    logger.warning(
                        "trade Dispute Statement acknowledgement background "
                        "recovery failed (%s)",
                        type(exc).__name__,
                    )
                    dispatch_report = {"has_more": False, "failed": 1}
                has_more = has_more or dispatch_report["has_more"]
                if has_more:
                    continue
                self._wake_event.wait(self._next_wait_seconds())
                self._wake_event.clear()
        finally:
            with self._lock:
                self._thread = None


class _MDNSPublisher:
    """Own a non-blocking mDNS advertisement for one web app."""

    def __init__(self, state: WebState) -> None:
        self._state = state
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._responder: Optional[Any] = None

    def start(self) -> None:
        with self._lock:
            if self._responder is not None:
                return
            if self._thread is not None and self._thread.is_alive():
                return
            self._cancel.clear()
            thread = threading.Thread(
                target=self._run,
                name="nth-mdns-publisher",
                daemon=True,
            )
            self._thread = thread
        thread.start()

    def stop(self) -> None:
        self._cancel.set()
        with self._lock:
            responder = self._responder
            self._responder = None
            self._state.mdns_responder = None
            thread = self._thread
        if responder is not None:
            try:
                responder.stop()
            except Exception as exc:  # noqa: BLE001
                logger.debug("mDNS responder stop failed: %s", exc)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=0.25)
            if thread.is_alive():
                logger.debug("mDNS publisher is still finishing in background")

    def _run(self) -> None:
        responder = _build_mdns_responder(self._state)
        if responder is None:
            self._clear_thread()
            return
        try:
            responder.start()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "LAN DID publish failed; node will NOT be discoverable "
                "on the local network: %s",
                exc,
            )
            self._clear_thread()
            return

        with self._lock:
            cancelled = self._cancel.is_set()
            if not cancelled:
                self._responder = responder
                self._state.mdns_responder = responder
            self._thread = None
        if cancelled:
            try:
                responder.stop()
            except Exception as exc:  # noqa: BLE001
                logger.debug("cancelled mDNS responder stop failed: %s", exc)
            return

        logger.info(
            "LAN DID publish active: network_id=%s did=%s "
            "pubkey_prefix=%s label=%r "
            "(set NTH_LAN_PUBLISH=0 to disable, "
            "NTH_LAN_LABEL=<text> to customise label)",
            getattr(responder, "agent_id", "?"),
            getattr(responder, "did", "") or "?",
            (getattr(responder, "pubkey_hex", "") or "?")[:16],
            getattr(responder, "label", ""),
        )

    def _clear_thread(self) -> None:
        with self._lock:
            self._thread = None

class _UDPLANPublisher:
    """Own the stdlib UDP discovery responder for explicit LAN mode."""

    def __init__(self, state: WebState) -> None:
        self._state = state
        self._lock = threading.Lock()
        self._responder: Optional[Any] = None

    def start(self) -> None:
        with self._lock:
            if self._responder is not None:
                return
            responder = _build_udp_lan_responder(self._state)
            if responder is None:
                return
            try:
                responder.start()
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning(
                    "UDP LAN publish failed; mDNS may still be available: %s",
                    exc,
                )
                return
            self._responder = responder
            self._state.lan_udp_responder = responder

    def stop(self) -> None:
        with self._lock:
            responder = self._responder
            self._responder = None
            self._state.lan_udp_responder = None
        if responder is not None:
            try:
                responder.stop()
            except OSError as exc:
                logger.debug("UDP LAN responder stop failed: %s", exc)


def _register_builtin_plugins(state: WebState) -> None:
    """Register reviewed adapters without granting or enabling effects."""

    from nth_dao.plugins.builtin import (
        register_curated_registry_discovery,
        register_federation_discovery,
        register_literal_intent_resolver,
        register_review_intent_solver,
        register_loopback_transport,
        register_memory_market_index,
        register_memory_message_store,
        register_mock_agent_provider,
    )
    from nth_dao.web import v2_api

    announce_self = None
    public_base_url = _configured_public_base_url()
    node_did = state.node_identity.as_did() if state.node_identity is not None else ""
    if public_base_url and node_did:
        try:
            from nth_dao.discovery.federation_registry import (
                normalize_learned_peer_url,
            )

            public_base_url = normalize_learned_peer_url(public_base_url)
        except ValueError:
            public_base_url = ""
        if public_base_url:
            def announce_self(peers):
                from nth_dao.web.market_federation_poll import announce_peer_hello

                return announce_peer_hello(
                    list(peers),
                    peer_url=public_base_url,
                    did=node_did,
                )

    register_federation_discovery(
        state.plugin_host,
        state.workspace,
        cache=state.market_fed_cache,
        get_seed_peers=lambda: v2_api._read_fed_peers(state.workspace),
        announce_self=announce_self,
        max_duration_s=v2_api._market_fed_cycle_budget_s(),
    )
    register_curated_registry_discovery(
        state.plugin_host,
        state.workspace,
        get_registry_url=lambda: os.environ.get("NTH_CURATED_REGISTRY_URL", ""),
        get_registry_publisher_did=lambda: os.environ.get(
            "NTH_CURATED_REGISTRY_PUBLISHER_DID", "",
        ),
    )
    register_mock_agent_provider(state.plugin_host)
    register_literal_intent_resolver(state.plugin_host)
    register_review_intent_solver(state.plugin_host)
    register_memory_market_index(state.plugin_host)
    register_memory_message_store(state.plugin_host)
    register_loopback_transport(state.plugin_host)


def create_app(
    workspace: str | Path | None = None,
    *,
    require_console_auth: bool | None = None,
    allow_unauthenticated_plugin_admin: bool = False,
) -> FastAPI:
    if type(allow_unauthenticated_plugin_admin) is not bool:
        raise TypeError("allow_unauthenticated_plugin_admin must be a boolean")
    if require_console_auth is None:
        # Existing unit tests construct explicit temporary workspaces and
        # assert route-level membership/permission semantics. The real
        # console entry points below call create_app() without an explicit
        # workspace (using NTH_WORKSPACE/env/default resolution) and keep
        # request authentication on by default.
        require_console_auth = workspace is None
    root = _resolve_safe_workspace(workspace)
    state = WebState(root)
    _bootstrap(state)
    try:
        _register_builtin_plugins(state)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("reviewed plugin registration failed (%s)", type(exc).__name__)
    mdns_publisher = _MDNSPublisher(state)
    udp_lan_publisher = _UDPLANPublisher(state)
    trade_execution_recovery = _TradeExecutionRecoveryWorker(state)
    trade_dispute_recovery = _TradeDisputeStatementRecoveryWorker(state)
    state.trade_dispute_statement_recovery_worker = trade_dispute_recovery

    # Network services are owned by FastAPI lifespan, not create_app().
    # This keeps application construction side-effect free and prevents
    # tests/tools that only inspect the ASGI app from leaking mDNS threads.
    # While lifespan is active, a per-app atexit callback still protects
    # normal interpreter shutdown.
    import atexit as _atexit

    shutdown_registered = False

    def _shutdown_runtime(app_instance: FastAPI) -> None:
        """Stop durable dispatch workers before tearing down the hub.

        AgentLink must stop accepting work before supervised child processes
        disappear. Jobs still waiting in a local queue are persisted as
        ``delivery_unknown`` by the manager; they are never silently dropped.
        """
        nth_state = getattr(app_instance.state, "nth", None)
        reconciler = getattr(nth_state, "commerce_reconciler", None)
        if reconciler is not None:
            try:
                if not reconciler.stop(timeout_s=10.0):
                    logger.warning("commerce reconciler is still stopping")
            except (RuntimeError, TypeError, ValueError) as exc:
                logger.warning(
                    "commerce reconciler shutdown failed (%s)",
                    type(exc).__name__,
                )
        manager = getattr(app_instance.state, "agent_link_manager", None)
        if manager is not None:
            try:
                manager.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("AgentLink manager shutdown failed: %s", exc)
        try:
            from .supervised_agent_plugin import disable_supervised_agent_plugins

            plugin_outcomes = disable_supervised_agent_plugins(app_instance)
            for plugin_id, outcome in plugin_outcomes.items():
                if outcome.startswith("cleanup-failed"):
                    logger.warning(
                        "supervised provider shutdown failed for %s: %s",
                        plugin_id,
                        outcome,
                    )
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("supervised provider shutdown failed: %s", exc)
        supervisor = getattr(app_instance.state, "v2_supervisor", None)
        if supervisor is not None:
            try:
                supervisor.shutdown()
            except Exception as exc:  # noqa: BLE001
                logger.warning("agent supervisor shutdown failed: %s", exc)
        trade_execution_recovery.stop()
        trade_dispute_recovery.stop()
        udp_lan_publisher.stop()
        mdns_publisher.stop()

    def _shutdown_at_exit() -> None:
        _shutdown_runtime(app)

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        nonlocal shutdown_registered
        v2_runtime = None
        try:
            mdns_publisher.start()
            udp_lan_publisher.start()
            trade_execution_recovery.start()
            trade_dispute_recovery.start()
            if not shutdown_registered:
                _atexit.register(_shutdown_at_exit)
                shutdown_registered = True
            try:
                from . import v2_api as v2_runtime

                v2_runtime.start_market_federation_runtime(_app)
            except Exception as exc:  # noqa: BLE001
                logger.warning("federation runtime startup failed: %s", exc)
            reconciler = getattr(state, "commerce_reconciler", None)
            if reconciler is not None:
                try:
                    reconciler.start()
                except (RuntimeError, TypeError, ValueError) as exc:
                    logger.warning(
                        "commerce reconciler startup failed (%s)",
                        type(exc).__name__,
                    )
            yield
        finally:
            if v2_runtime is not None:
                try:
                    v2_runtime.stop_market_federation_runtime(_app)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("federation runtime shutdown failed: %s", exc)
            _shutdown_runtime(_app)
            if shutdown_registered:
                _atexit.unregister(_shutdown_at_exit)
                shutdown_registered = False

    app = FastAPI(
        title="NTH DAO Console",
        description="Local-first web console for NTH DAO membership, groups, tasks, and audit.",
        version="0.9.0",
        lifespan=_lifespan,
    )
    app.add_middleware(_FederationBodyLimitMiddleware)

    app.state.nth = state
    app.state.market_fed_cache = state.market_fed_cache
    app.state.nth_console_token = _load_or_create_console_token()
    app.state.nth_require_console_auth = require_console_auth
    app.state.nth_allow_unauthenticated_plugin_admin = (
        allow_unauthenticated_plugin_admin
    )
    app.state.nth_public_base_url = _configured_public_base_url()
    # 公网部署可关掉"页面内嵌 token"(NTH_CONSOLE_TOKEN_IN_PAGE=0)。
    app.state.nth_embed_console_token = _embed_console_token_in_page()

    def _is_a2a_rest_endpoint(path: str) -> bool:
        """A2A v1.0.1 HTTP+JSON root routes that must share /api auth."""
        if path in (
            "/message:send",
            "/message:stream",
            "/tasks",
            "/extendedAgentCard",
        ):
            return True
        return path.startswith("/tasks/")

    def _request_client_is_loopback(request: Request) -> bool:
        host = str(request.client.host if request.client else "").strip()
        if host.lower() == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _is_public_v2_protocol_read(path: str) -> bool:
        """Allow only read endpoints required by federation protocols."""

        if path in {
            "/api/v2/health",
            "/api/v2/market/open",
            "/api/v2/market/categories",
            "/api/v2/market/federation/digest",
            "/api/v2/market/federation/pull",
            "/api/v2/market/federation/peers",
            "/api/v2/social/federation/pull",
        }:
            return True
        trade_offer_prefix = "/api/v2/trade/federation/offers/"
        if path.startswith(trade_offer_prefix):
            suffix = path[len(trade_offer_prefix):]
            if (
                len(suffix) == 71
                and suffix.startswith("sha256:")
                and all(character in "0123456789abcdef" for character in suffix[7:])
            ):
                return True
            return re.fullmatch(
                r"sha256:[0-9a-f]{64}/rule-packages/sha256:[0-9a-f]{64}",
                suffix,
            ) is not None
        return path.startswith("/api/v2/commerce/federation/listings/")

    @app.middleware("http")
    async def _console_auth_middleware(request: Request, call_next):
        # Public identity card (2026-06-08): the ``.well-known`` family
        # is the canonical place for "anyone, even strangers, may
        # fetch this" metadata. Other NTH DAO nodes scanning the LAN
        # need to be able to pull this without owning the operator's
        # console Bearer token, otherwise the cross-node discovery
        # story is broken.
        # L0-2 (2026-06-08): A2A Protocol AgentCard is published at
        # ``/.well-known/agent.json`` per A2A convention; same
        # unauthenticated-public contract as the NTH-native card.
        # Both share the underlying Ed25519 identity material so a
        # consumer that knows the pubkey can cross-verify the two.
        if request.url.path in (
            "/.well-known/nth-dao/identity.json",
            "/.well-known/agent-card.json",
            "/.well-known/agent.json",
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # Phase 1 v2 read endpoints (2026-06-10): the local hub
        # console v2 surface is a read-only mirror of public
        # operational state (processes, missions, decisions,
        # receipts, rules, agents — same things the operator can
        # already see in the v1 dashboard). Bound to 127.0.0.1
        # only via the server bind. Tagged anonymous so the v2
        # SPA — which loads in a browser tab that does NOT have
        # the console_token — can populate without forcing the
        # operator into a login dance for a localhost preview.
        # Phase 2 will introduce per-action cap_token checks at
        # each POST/PATCH endpoint; the read surface stays open.
        # 2026-06-13 hardening: ONLY safe (read) methods ride the
        # anonymous bypass. Action endpoints under /api/v2/ —
        # spawn / stop / agents/{did}/ask[-stream] — are
        # state-changing and, in ask's case, drive a spawned agent
        # under its hub-held cap_token authority (and, by default,
        # a2a:message_send onto the network). Letting an
        # unauthenticated caller (incl. a CSRF POST from a visited
        # webpage) wield that is a confused-deputy hole. So writes
        # fall through to the normal auth path: open when console
        # auth is disabled (local default), Bearer/CapToken-gated
        # when it's on. This is the "Phase 2 per-action cap_token
        # checks" the read-surface comment promised.
        if request.url.path.startswith("/api/v2/") and request.method in (
            "GET", "HEAD", "OPTIONS",
        ) and (
            _request_client_is_loopback(request)
            or _is_public_v2_protocol_read(request.url.path)
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # 跨 DAO 认领提交(XDAO-2,crypto-authorized):外部 DAO 的 agent 提交
        # 已签名的认领。授权靠 record_foreign_claim 的逐项验签(收据 publisher
        # 自验 + cap_token + 绑定),**不需要本节点的 console token**(外部节点
        # 没有)。匿名放行,与联邦读端点同理——攻击者最多提交一个密码学合法
        # 的认领(=正当行为),无法伪造,也不借用 hub 任何权限(非 confused
        # deputy:端点只是把自授权的认领落 CAS,不驱动本地 agent/网络)。
        if (
            request.method == "POST"
            and request.url.path.startswith("/api/v2/market/")
            and request.url.path.endswith("/claim-foreign")
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # Federation hello is an anonymous, crypto-authorized discovery hint.
        # The handler never trusts the submitted URL/DID: it enforces public
        # HTTPS, pins DNS, fetches the remote signed identity card, and rate
        # limits callers before persisting a bounded TTL record.
        if (
            request.method == "POST"
            and request.url.path == "/api/v2/market/federation/hello"
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # Commerce replication is authenticated by a signed, content-bound
        # envelope whose target DID must equal this node. Remote DAOs cannot
        # possess the operator's console token; the handler performs the
        # cryptographic authorization and bounded persistence instead.
        if (
            request.method == "POST"
            and request.url.path == "/api/v2/commerce/federation/sync"
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # A seller may issue a Cart only for a valid, signed Intent that
        # explicitly allow-lists the seller DID and a local signed Listing.
        # This is the commerce equivalent of an authenticated quote request;
        # remote buyers do not possess the seller console token.
        if (
            request.method == "POST"
            and request.url.path == "/api/v2/commerce/carts"
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # A remote taker cannot possess the operator console token. This
        # route accepts only a short-lived, destination-bound DID-signed
        # Proposal delivery; the handler performs rate limiting, signature
        # verification, local Offer/Rule replay, CAS retention, and Spine
        # projection before acknowledging it.
        if (
            request.method == "POST"
            and request.url.path == "/api/v2/trade/federation/proposals"
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # A maker returns the fully signed accepted Order to its taker.
        # The remote maker cannot possess this node's console token; the
        # handler validates destination, freshness, nested signatures, and
        # bounded persistence before acknowledging the agreement.
        if (
            request.method == "POST"
            and request.url.path == "/api/v2/trade/federation/orders"
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # Receipt delivery is authenticated by its destination-bound DID
        # signature.  The handler additionally requires an exact local Order,
        # replays local execution policy, and retains CAS/Spine evidence before
        # returning a receiver-signed acknowledgement.
        if (
            request.method == "POST"
            and re.fullmatch(
                r"/api/v2/trade/federation/orders/"
                r"sha256:[0-9a-f]{64}/execution-receipts",
                request.url.path,
            )
            is not None
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # Receipt Review delivery is likewise authenticated by the review,
        # destination-bound envelope, signed policy snapshots, and freshness
        # checks. Remote counterparties cannot possess the console token.
        if (
            request.method == "POST"
            and re.fullmatch(
                r"/api/v2/trade/federation/orders/"
                r"sha256:[0-9a-f]{64}/execution-receipts/[^/]+/reviews",
                request.url.path,
            )
            is not None
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # A Dispute Statement is a signed counterparty claim, not an operator
        # command. The route replays the exact local Order, Receipt, Review,
        # and Rule Package before bounded retention and a receiver-signed ACK.
        if (
            request.method == "POST"
            and _TRADE_DISPUTE_STATEMENT_DELIVERY_PATH.fullmatch(request.url.path)
            is not None
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # Exact Statement retrieval is authorized by a short-lived signed
        # Fetch Request whose requester and responder are both bound to the
        # retained bilateral Order. Remote counterparties cannot possess the
        # operator console token, so the handler performs the cryptographic,
        # replay, quota, and audit checks before disclosing any Statement.
        if (
            request.method == "POST"
            and _TRADE_DISPUTE_STATEMENT_FETCH_FEDERATION_PATH.fullmatch(
                request.url.path
            )
            is not None
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        if not require_console_auth:
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)
        if (
            not request.url.path.startswith("/api/")
            and not _is_a2a_rest_endpoint(request.url.path)
        ):
            request.state.nth_principal = {"type": "anonymous"}
            return await call_next(request)

        # L1-3 (2026-06-08): try the CapToken scheme FIRST. If the
        # caller presents a CapToken header that authenticates AND
        # passes signature + time + revocation checks, accept it and
        # tag the request with the principal so endpoint handlers
        # can later enforce capability-level access. The capability
        # vs. method check (e.g. "is a2a:message_send in the
        # capabilities list?") happens at the handler, not here —
        # the middleware only proves WHO is calling, not WHAT they
        # may do.
        cap_raw = _extract_cap_token_auth(request)
        if cap_raw:
            tok = _decode_cap_auth(cap_raw)
            if tok is None:
                return JSONResponse(
                    {
                        "detail": (
                            "Authorization: CapToken value is not "
                            "valid base64url-canonical-JSON"
                        ),
                    },
                    status_code=401,
                )
            ok, reason = _verify_cap_token(
                tok,
                revoked_ids=state.cap_tokens.revoked_set(),
            )
            if not ok:
                logger.info(
                    "cap_token rejected (%s): token_id=%s",
                    reason, tok.get("token_id", "?"),
                )
                return JSONResponse(
                    {
                        "detail": (
                            f"cap_token rejected: {reason}"
                        ),
                    },
                    status_code=401,
                )
            request.state.nth_principal = {
                "type": "cap_token",
                "token": tok,
            }
            return await call_next(request)

        # Console Bearer path (operator full access)
        supplied = _extract_bearer_token(request)
        expected = str(app.state.nth_console_token)
        if not supplied or not hmac.compare_digest(supplied, expected):
            return JSONResponse(
                {"detail": "missing or invalid console token"},
                status_code=401,
            )
        request.state.nth_principal = {"type": "console"}
        return await call_next(request)

    # Public identity card (2026-06-08): a signed JSON blob that
    # describes "who is this NTH DAO node?" - DID, pubkey, capabilities,
    # issued_at - intended for unauthenticated cross-node fetch over
    # the LAN. Distinct from /api/identity which is the operator's
    # console-private endpoint.
    #
    # The card is signed by the node identity itself, so any consumer
    # who already trusts a pubkey can verify the card without external
    # PKI. The signature covers a canonical JSON of every field except
    # ``sig`` itself.
    @app.get("/.well-known/nth-dao/identity.json")
    def public_identity_card(request: Request) -> dict[str, Any]:
        if state.node_identity is None:
            # Honest 503: this node has not bootstrapped an identity
            # (typically PyNaCl missing). Cross-LAN consumers see a
            # clear "this node is not in the federation right now"
            # rather than a misleading empty card.
            raise HTTPException(
                status_code=503,
                detail=("node identity unavailable; install pynacl + restart"),
            )
        ident = state.node_identity
        pubkey_hex = getattr(ident, "pubkey_hex", "") or ""
        challenge = str(request.query_params.get("challenge") or "").strip()
        if challenge and re.fullmatch(r"[0-9a-f]{64}", challenge) is None:
            raise HTTPException(
                status_code=400,
                detail="identity challenge must be 32 bytes of lowercase hex",
            )
        # The card content. Order is significant for canonical_json
        # but we don't enforce key order here - the signing helper
        # does it for us by sorting keys.
        # Prefer the operator-advertised public/LAN base so the signed card
        # binds the same URL that LAN/mDNS discovery publishes. Falling back
        # to the request host keeps local development and TestClient stable.
        base_url = _configured_public_base_url() or str(request.base_url).rstrip("/")
        card: dict[str, Any] = {
            "kind": "nth-dao-identity-card-v1",
            "agent_id": DEFAULT_ADMIN_ID,
            "did": _safe_did(ident),
            "pubkey_hex": pubkey_hex,
            # R-53 (2026-06-08): include the visible code as a
            # convenience for consumers who want to display a friendly
            # handle without re-implementing code_for_pubkey. Any
            # cross-language port can recompute it independently and
            # cross-check against this field. The canonical spec is:
            #   code = sha256(pubkey_hex.encode("utf-8")).hexdigest()[:8]
            #   formatted as "XXXX-XXXX"
            # i.e. the hash is over the hex-string, NOT the raw bytes
            # (documented here so a Rust/Go port doesn't accidentally
            # hash bytes.fromhex(pubkey_hex) and produce a different
            # value).
            "code": code_for_pubkey(pubkey_hex),
            "capabilities": [],   # reserved; future protocol versions
                                  # can populate from agent profile
            "issued_at": datetime.now().isoformat(),
            # L0-2 (2026-06-08): cross-link to the A2A-compatible
            # mirror at /.well-known/agent.json so a consumer that
            # only knows our native card can discover the A2A view
            # without a second well-known probe.
            #
            # B5 (review fix 2026-06-08): use the FULL request URL.
            # A relative path breaks if a consumer caches the card
            # to disk and later parses it without the original base
            # URL context (no way to recover the host); absolute URL
            # remains resolvable in every consumer state.
            "a2a_card_url": f"{base_url}/.well-known/agent.json",
            # Federation directory: the public, unauthenticated endpoints a
            # peer needs to pull this DAO's signed task/product/service feed.
            # Discovery sources (LAN/mDNS/DNS/seed peer gossip) should point
            # at ``federation.peer_url`` and let the digest/full-announcement
            # signatures decide what is trustworthy.
            "base_url": base_url,
            "federation": _federation_directory(base_url),
        }
        if challenge:
            card["challenge"] = challenge
        # Sign the card so a remote consumer who already has our
        # pubkey can verify they're talking to the right node.
        # ``sign_json`` is the same primitive used everywhere else in
        # the codebase (mandates, endorsements, group records).
        try:
            sig = ident.sign_json(card)
        except Exception as exc:  # noqa: BLE001
            logger.warning("public identity card sign failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="identity card signing unavailable",
            ) from exc
        card["sig"] = sig
        return card
    # L0-2 (2026-06-08): A2A Protocol AgentCard mirror.
    #
    # The A2A spec (a2aproject/A2A specification/a2a.proto) defines
    # a JSON metadata document at a well-known URL describing an
    # agent's identity, capabilities and authentication. 50+ partners
    # ship A2A-capable clients (Atlassian / Cohere / Salesforce /
    # PayPal / SAP / LangChain / …). Emitting this view costs ~80
    # lines and instantly makes any NTH DAO node a first-class A2A
    # participant.
    #
    # Signing uses JWS-EdDSA detached payload (RFC 7515 §A.5 style):
    # the AgentCard JSON IS the payload, and the signatures[] envelope
    # is a JWS Compact serialization with empty in-band payload.
    # The signing keypair is the same workspace Ed25519 identity that
    # signs /.well-known/nth-dao/identity.json — a consumer who
    # already has our pubkey can verify EITHER card.
    @app.get("/.well-known/agent-card.json")
    @app.get("/.well-known/agent.json")
    def a2a_public_agent_card(request: Request) -> Response:
        if state.node_identity is None:
            # Mirror the NTH-native card's 503 contract — a public
            # endpoint that returns an unsigned-or-fake card poisons
            # the consumer's trust store.
            raise HTTPException(
                status_code=503,
                detail=("node identity unavailable; install pynacl + restart"),
            )
        # A4 (architect review 2026-06-08): a2a_card helpers are at
        # module scope (same convention as R-58's did_key hoist).
        ident = state.node_identity
        pubkey_hex = getattr(ident, "pubkey_hex", "") or ""
        did = _safe_did(ident)
        if not did or not pubkey_hex:
            # Defence in depth: a node_identity that exists but lacks
            # crypto material would emit an unverifiable A2A card.
            raise HTTPException(
                status_code=503,
                detail=(
                    "node identity has no usable keypair; install pynacl + restart"
                ),
            )

        # Resolve home channel id for the placeholder skill example.
        # ``DEFAULT_CHANNEL_ID`` is the always-present home channel
        # (imported from nth_dao.groups at the top of this module).
        home_channel = DEFAULT_CHANNEL_ID

        base_url = str(request.base_url).rstrip("/")
        # B7 (2026-06-08): pass the REAL skill list rather than relying
        # on the build_a2a_card fallback. ``known_skills(state)``
        # introspects this node's wired subsystems and emits one
        # AgentSkill per actually-reachable surface.
        skills = _known_a2a_skills(state, base_url=base_url)
        card = _build_a2a_card(
            agent_id=DEFAULT_ADMIN_ID,
            did=did,
            pubkey_hex=pubkey_hex,
            base_url=base_url,
            home_channel_id=home_channel,
            skills=skills,
        )
        try:
            sig_env = _sign_a2a_card_jws(card, ident, did)
        except Exception as exc:  # noqa: BLE001
            logger.warning("A2A card sign failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="A2A agent card signing unavailable",
            ) from exc
        card["signatures"] = [sig_env]

        # B4 (review fix 2026-06-08): ETag + Cache-Control.
        # The A2A card body has NO time-varying field (no issued_at;
        # signature is deterministic for a given input), so the body
        # is stable until either (a) the workspace identity rotates
        # or (b) the build_a2a_card output changes — both rare.
        # ETag = sha256(canonical_json(card)) gives consumers a cheap
        # If-None-Match → 304 path so an A2A consumer polling at 60s
        # doesn't burn a fresh Ed25519 sign on every request. The
        # 5-minute max-age is a soft hint; ETag is the authoritative
        # freshness signal.
        #
        # NOTE: native /.well-known/nth-dao/identity.json deliberately
        # carries ``issued_at: datetime.now()`` so its body changes
        # every request — ETag would never hit there. Adding ETag
        # only here, not the native endpoint, is the correct asymmetry.
        from nth_dao.identity import canonical_json as _canonical_json

        body_bytes = _canonical_json(card)
        etag = '"' + hashlib.sha256(body_bytes).hexdigest()[:32] + '"'

        if_none_match = request.headers.get("If-None-Match", "")
        if if_none_match and if_none_match.strip() == etag:
            return Response(
                status_code=304,
                headers={
                    "ETag": etag,
                    "Cache-Control": "public, max-age=300",
                    "A2A-Version": _A2A_SPEC_VERSION,
                },
            )

        return Response(
            content=body_bytes,
            media_type="application/json",
            headers={
                "ETag": etag,
                "Cache-Control": "public, max-age=300",
                    "A2A-Version": _A2A_SPEC_VERSION,
            },
        )

    # L1-2 (2026-06-08): A2A Protocol JSON-RPC endpoint.
    #
    # Lets external A2A consumers (LangChain / Cohere / Salesforce /
    # PayPal / SAP A2A clients) submit tasks to this NTH DAO node.
    # Methods implemented: ``message/send``, ``tasks/get``,
    # ``tasks/cancel``. The receipt subsystem (L1-1) emits a signed
    # work-proof per accepted message, so the consumer can later prove
    # the agent executed the work it claims.
    #
    # Path: ``/api/a2a/rpc`` (gated by console_token like other /api/
    # endpoints; an external A2A consumer must present the token).
    # JSON-RPC 2.0 envelope per a2aprotocol.ai convention.
    @app.post("/api/a2a/rpc")
    async def a2a_rpc_endpoint(request: Request) -> dict[str, Any]:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "parse error: body is not valid JSON",
                },
            }
        if not isinstance(payload, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "invalid request: body must be a JSON object",
                },
            }
        # L1-3 (2026-06-08): pass the auth-resolved principal to the
        # handler so it can enforce per-method capability + task
        # scope. Console principals get full access; cap-token
        # principals are narrowly checked.
        # L1-4 (2026-06-08): mission_store enables tasks/split and
        # mission-progress enrichment on tasks/get responses.
        handler = A2ARPCHandler(
            task_store=state.a2a_tasks,
            receipt_store=state.receipts,
            identity=state.node_identity,
            principal=get_request_principal(request),
            mission_store=state.missions,
        )
        return handler.handle(payload)

    # A2A v1.0.1 HTTP+JSON binding. These endpoints are root-level by
    # spec, so the middleware above explicitly routes them through the
    # same principal resolution as /api/a2a/rpc when console auth is on.
    _A2A_REST_MEDIA_TYPE = "application/a2a+json"

    def _a2a_rest_headers() -> dict[str, str]:
        return {"A2A-Version": _A2A_SPEC_VERSION}

    def _a2a_rest_response(
        payload: Any,
        *,
        status_code: int = 200,
    ) -> JSONResponse:
        return JSONResponse(
            payload,
            status_code=status_code,
            media_type=_A2A_REST_MEDIA_TYPE,
            headers=_a2a_rest_headers(),
        )

    def _a2a_rest_error(
        code: int,
        message: str,
        *,
        status_code: int,
        data: Any = None,
    ) -> JSONResponse:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return _a2a_rest_response({"error": err}, status_code=status_code)

    def _a2a_reject_incompatible_version(request: Request) -> Optional[JSONResponse]:
        requested = (request.headers.get("A2A-Version") or "").strip()
        if not requested:
            return None
        if requested.split(".", 1)[0] != _A2A_SPEC_VERSION.split(".", 1)[0]:
            return _a2a_rest_error(
                -32600,
                "unsupported A2A major version",
                status_code=400,
                data={"requested": requested, "supported": _A2A_SPEC_VERSION},
            )
        return None

    async def _a2a_read_json_object(request: Request) -> dict[str, Any] | JSONResponse:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return _a2a_rest_error(
                -32700,
                "parse error: body is not valid JSON",
                status_code=400,
            )
        if not isinstance(payload, dict):
            return _a2a_rest_error(
                -32600,
                "invalid request: body must be a JSON object",
                status_code=400,
            )
        return payload

    def _a2a_handler_for_request(request: Request) -> A2ARPCHandler:
        return A2ARPCHandler(
            task_store=state.a2a_tasks,
            receipt_store=state.receipts,
            identity=state.node_identity,
            principal=get_request_principal(request),
            mission_store=state.missions,
        )

    def _a2a_status_for_rpc_error(code: Any) -> int:
        if code == -32001:  # TaskNotFoundError
            return 404
        if code == -32003:  # cap-token forbidden
            return 403
        if code in (-32700, -32600, -32602):
            return 400
        if code == -32601:
            return 404
        return 500

    def _a2a_rest_from_rpc(rpc_body: dict[str, Any], *, send_response: bool = False) -> JSONResponse:
        if "error" in rpc_body:
            err = rpc_body.get("error") or {}
            return _a2a_rest_error(
                int(err.get("code", -32603)),
                str(err.get("message", "A2A request failed")),
                status_code=_a2a_status_for_rpc_error(err.get("code")),
                data=err.get("data"),
            )
        result = rpc_body.get("result")
        if send_response:
            return _a2a_rest_response({"task": result})
        return _a2a_rest_response(result)

    def _a2a_int_query(
        request: Request,
        name: str,
        *,
        default: Optional[int] = None,
        minimum: int = 0,
        maximum: int = 100,
    ) -> Optional[int]:
        raw = request.query_params.get(name)
        if raw in (None, ""):
            return default
        try:
            value = int(raw)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"{name} must be an integer") from exc
        if value < minimum or value > maximum:
            raise HTTPException(status_code=400, detail=f"{name} must be between {minimum} and {maximum}")
        return value

    def _a2a_shape_task_for_rest(
        task: dict[str, Any],
        *,
        history_length: Optional[int] = None,
        include_artifacts: bool = True,
    ) -> dict[str, Any]:
        shaped = json.loads(json.dumps(task, ensure_ascii=False))
        if history_length is not None:
            shaped["history"] = list(shaped.get("history") or [])[-history_length:] if history_length else []
        if not include_artifacts:
            shaped["artifacts"] = []
        return shaped

    @app.post("/message:send")
    async def a2a_message_send(request: Request) -> JSONResponse:
        version_error = _a2a_reject_incompatible_version(request)
        if version_error is not None:
            return version_error
        payload = await _a2a_read_json_object(request)
        if isinstance(payload, JSONResponse):
            return payload
        rpc_body = _a2a_handler_for_request(request).handle({
            "jsonrpc": "2.0",
            "id": "rest-message-send",
            "method": "message/send",
            "params": payload,
        })
        return _a2a_rest_from_rpc(rpc_body, send_response=True)

    @app.post("/message:stream")
    async def a2a_message_stream(request: Request) -> JSONResponse:
        version_error = _a2a_reject_incompatible_version(request)
        if version_error is not None:
            return version_error
        return _a2a_rest_error(
            -32004,
            "UnsupportedOperationError: streaming is not enabled on this node",
            status_code=501,
            data={"capabilities.streaming": False},
        )

    @app.get("/tasks")
    def a2a_tasks_list(request: Request) -> JSONResponse:
        version_error = _a2a_reject_incompatible_version(request)
        if version_error is not None:
            return version_error
        page_size = _a2a_int_query(request, "pageSize", default=50, minimum=1, maximum=100) or 50
        page_token = _a2a_int_query(request, "pageToken", default=0, minimum=0, maximum=10_000_000) or 0
        history_length = _a2a_int_query(request, "historyLength", default=None, minimum=0, maximum=100)
        include_artifacts = (request.query_params.get("includeArtifacts") or "true").lower() != "false"
        context_id = request.query_params.get("contextId") or ""
        status_filter = request.query_params.get("status") or ""
        tasks: list[dict[str, Any]] = []
        for task_id in state.a2a_tasks.all_ids():
            task = state.a2a_tasks.get(task_id)
            if not isinstance(task, dict):
                continue
            if context_id and task.get("context_id") != context_id:
                continue
            if status_filter and (task.get("status") or {}).get("state") != status_filter:
                continue
            tasks.append(_a2a_shape_task_for_rest(
                task,
                history_length=history_length,
                include_artifacts=include_artifacts,
            ))
        total_size = len(tasks)
        page = tasks[page_token:page_token + page_size]
        next_offset = page_token + len(page)
        return _a2a_rest_response({
            "tasks": page,
            "nextPageToken": str(next_offset) if next_offset < total_size else "",
            "pageSize": page_size,
            "totalSize": total_size,
        })

    @app.post("/tasks/{task_id}:cancel")
    async def a2a_task_cancel(request: Request, task_id: str) -> JSONResponse:
        version_error = _a2a_reject_incompatible_version(request)
        if version_error is not None:
            return version_error
        payload = await _a2a_read_json_object(request)
        if isinstance(payload, JSONResponse):
            return payload
        params = dict(payload)
        params["id"] = task_id
        rpc_body = _a2a_handler_for_request(request).handle({
            "jsonrpc": "2.0",
            "id": "rest-task-cancel",
            "method": "tasks/cancel",
            "params": params,
        })
        return _a2a_rest_from_rpc(rpc_body)

    @app.get("/tasks/{task_id:path}")
    def a2a_task_get(request: Request, task_id: str) -> JSONResponse:
        version_error = _a2a_reject_incompatible_version(request)
        if version_error is not None:
            return version_error
        history_length = _a2a_int_query(request, "historyLength", default=None, minimum=0, maximum=100)
        rpc_body = _a2a_handler_for_request(request).handle({
            "jsonrpc": "2.0",
            "id": "rest-task-get",
            "method": "tasks/get",
            "params": {"id": task_id},
        })
        response = _a2a_rest_from_rpc(rpc_body)
        if response.status_code != 200 or history_length is None:
            return response
        body = json.loads(response.body.decode("utf-8"))
        return _a2a_rest_response(_a2a_shape_task_for_rest(body, history_length=history_length))

    @app.get("/extendedAgentCard")
    def a2a_extended_agent_card(request: Request) -> Response:
        version_error = _a2a_reject_incompatible_version(request)
        if version_error is not None:
            return version_error
        return a2a_public_agent_card(request)

    # L1-3 (2026-06-08): capability-token endpoints.
    #
    # - POST /api/cap_tokens/issue   : admin-only, signs a token
    # - POST /api/cap_tokens/revoke  : admin-only, blacklists a token_id
    # - GET  /api/cap_tokens/{id}    : admin-only, audit lookup
    #
    # ``admin-only`` here means "principal must be console". An
    # operator with a cap_token CANNOT itself issue further cap_tokens
    # — delegation is not transitive in v1. Allowing transitive
    # delegation without a careful capability-chain proof would be a
    # privilege-escalation vector; we close it now and revisit if a
    # real use case appears.
    def _require_console_principal(request: Request) -> None:
        principal = get_request_principal(request)
        if principal.get("type") != "console":
            raise HTTPException(
                status_code=403,
                detail=(
                    "cap_token administration requires the console "
                    "principal (delegation is not transitive)"
                ),
            )

    @app.post("/api/cap_tokens/issue")
    def cap_tokens_issue(
        request: Request, payload: IssueCapTokenPayload,
    ) -> dict[str, Any]:
        _require_console_principal(request)
        if state.node_identity is None:
            raise HTTPException(
                status_code=503,
                detail=("node identity unavailable; install pynacl + restart"),
            )
        # Reject unknown capability strings:
        #   * Known caps (KNOWN_CAPABILITIES) — accept
        #   * Custom caps in NTH-OWNED namespaces (``a2a:``, ``nth:``)
        #     — REJECT as likely typos
        #   * Custom caps in external namespaces (``orgname:action``)
        #     — accept for forward compat
        #   * Anything not namespaced and not in KNOWN_CAPABILITIES —
        #     REJECT
        _OWNED_NAMESPACES = ("a2a", "nth")
        for cap in payload.capabilities:
            if cap in _CAP_KNOWN:
                continue
            if ":" not in cap:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"unknown capability {cap!r}. Must be one of "
                        f"{sorted(_CAP_KNOWN)} or a namespaced form "
                        f"like ``orgname:action`` (NTH-owned "
                        f"namespaces ``a2a:`` and ``nth:`` only "
                        f"accept the known set)."
                    ),
                )
            namespace = cap.split(":", 1)[0]
            if namespace in _OWNED_NAMESPACES:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"unknown capability {cap!r} in NTH-owned "
                        f"namespace {namespace!r}; this is almost "
                        f"certainly a typo. Known caps: "
                        f"{sorted(_CAP_KNOWN)}"
                    ),
                )
            # external namespace — alphanum / dash / underscore check
            if not all(
                p.replace("-", "").replace("_", "").isalnum()
                for p in cap.split(":", 1)
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"malformed capability {cap!r}; alnum + "
                        f"``-``/``_`` only in each side of the colon."
                    ),
                )
        try:
            tok = _sign_cap_token(
                issuer=state.node_identity,
                subject_did=payload.subject_did,
                capabilities=payload.capabilities,
                scope_task_id=payload.scope_task_id,
                scope_dao=payload.scope_dao,
                scope_model_allowlist=payload.scope_model_allowlist,
                ttl_ms=payload.ttl_ms,
                token_id=payload.token_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            state.cap_tokens.record(tok)
        except (OSError, ValueError) as exc:
            logger.error(
                "cap_token audit record write failed: %s", exc,
            )
            raise HTTPException(
                status_code=500,
                detail=f"cap_token audit persistence failed: {exc}",
            ) from exc
        return {
            "token": tok,
            # Convenience for the operator UI: paste this verbatim
            # into an ``Authorization:`` header to act as the subject.
            "authorization_header_value": (
                f"{AUTH_SCHEME_CAP_TOKEN} {_encode_cap_auth(tok)}"
            ),
        }

    @app.post("/api/cap_tokens/revoke")
    def cap_tokens_revoke(
        request: Request, payload: RevokeCapTokenPayload,
    ) -> dict[str, Any]:
        _require_console_principal(request)
        try:
            changed = state.cap_tokens.revoke(payload.token_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"token_id": payload.token_id, "changed": changed}

    @app.get("/api/cap_tokens/{token_id}")
    def cap_tokens_get(
        request: Request, token_id: str,
    ) -> dict[str, Any]:
        _require_console_principal(request)
        rec = state.cap_tokens.get(token_id)
        if rec is None:
            raise HTTPException(
                status_code=404,
                detail=f"cap_token {token_id!r} not in audit store",
            )
        return {
            "token": rec,
            "revoked": token_id in state.cap_tokens.revoked_set(),
        }

    # DID bootstrap (2026-06-07): /api/identity is the "who is this
    # NTH DAO node?" endpoint. Other downloads can fetch this URL
    # (via LAN / relay) to learn how to address this node by DID.
    # Member-gated per R-1: no API surface is exposed to unauthenticated
    # callers, even when the data inside is technically public.
    @app.get("/api/identity")
    def identity_endpoint(actor_id: str = "") -> dict[str, Any]:
        if not actor_id:
            raise HTTPException(
                status_code=400,
                detail="actor_id is required for identity endpoint",
            )
        _require_member(state, actor_id)
        if state.node_identity is None:
            # R-46 (2026-06-08): no crypto -> empty code (NOT the
            # literal "admin" hash, which would collide globally
            # across every PyNaCl-missing install). bootstrap_error
            # tells the front-end why and lets it render a help
            # tooltip rather than a stale-looking handle.
            return {
                "agent_id": DEFAULT_ADMIN_ID,
                "did": "",
                "pubkey_hex": "",
                "pubkey_prefix": "",
                "code": "",
                "bootstrap_error": (
                    "node identity unavailable; install pynacl + restart"
                ),
            }
        ident = state.node_identity
        pk = getattr(ident, "pubkey_hex", "") or ""
        # R-46 (2026-06-08): identity object exists but carries no
        # pubkey (e.g. PyNaCl-missing path that constructs an
        # ``AgentIdentity.from_string`` placeholder). Surface this as
        # a bootstrap_error so the front-end shows a help hint
        # instead of an empty-but-silent handle row.
        bootstrap_error = (
            "" if pk else
            "node identity has no crypto material; install pynacl + restart"
        )
        return {
            "agent_id": DEFAULT_ADMIN_ID,
            "did": _safe_did(ident),
            # ``pubkey_hex`` is the public key - safe to share, that is
            # the WHOLE POINT of a pubkey. The PRIVATE key never leaves
            # ``<workspace>/identity/identity.json`` (mode 0600).
            "pubkey_hex": pk,
            "pubkey_prefix": pk[:16],
            # R-47 (2026-06-08): go through the single helper so
            # ``/api/identity``, ``/api/summary.actor_code`` and the
            # search admin row cannot drift apart on a future change.
            "code": _code_for_admin(state),
            "bootstrap_error": bootstrap_error,
        }

    # Week-1 Task 5 + Architect R-2 (2026-06-07): build identifier the
    # dashboard pins in the top bar. Pre-fix this endpoint spawned a git
    # subprocess on every call (DoS + info leak); now the rev is
    # captured ONCE at import time and the endpoint is gated by the
    # same member check the rest of the console uses.
    @app.get("/api/build_id")
    def build_id_endpoint(actor_id: str = "") -> dict[str, Any]:
        if not actor_id:
            raise HTTPException(
                status_code=400,
                detail="actor_id is required for build_id",
            )
        _require_member(state, actor_id)
        return {
            "backend_git": _BACKEND_GIT_REV,
            "backend_started_at": _BACKEND_STARTED_AT,
            "now": datetime.now().isoformat(),
        }

    @app.get("/api/plugins")
    def plugin_status_endpoint(actor_id: str = "") -> dict[str, Any]:
        if not actor_id:
            raise HTTPException(status_code=400, detail="actor_id is required")
        _require_member(state, actor_id)
        audit_ok, _audit_reason = state.plugin_host.verify_audit()
        incomplete_refreshes = []
        if audit_ok:
            try:
                incomplete_refreshes = list(
                    state.plugin_host.incomplete_refreshes()
                )
            except PluginAuditError:
                audit_ok = False
        return {
            "host_api": state.plugin_host.host_api,
            "audit": {
                "ok": audit_ok,
                "reason": "ok" if audit_ok else "verification-failed",
            },
            "incomplete_refreshes": incomplete_refreshes,
            "plugins": [
                {
                    "plugin_id": item.plugin_id,
                    "state": item.state,
                    "desired_enabled": item.desired_enabled,
                    "declared_permissions": list(item.declared_permissions),
                    "authorized_permissions": list(item.authorized_permissions),
                    "provided_capabilities": list(item.provided_capabilities),
                    "risk_tier": item.risk_tier,
                    "last_error_type": (
                        item.last_error.partition(":")[0][:128]
                        if item.last_error
                        else ""
                    ),
                }
                for item in state.plugin_host.list_status()
            ],
        }

    def _plugin_status_or_404(plugin_id: str):
        try:
            return state.plugin_host.status(plugin_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="plugin not found") from exc

    def _plugin_status_document(plugin_id: str) -> dict[str, Any]:
        item = _plugin_status_or_404(plugin_id)
        error_type = item.last_error.partition(":")[0] if item.last_error else ""
        return {
            "plugin_id": item.plugin_id,
            "state": item.state,
            "desired_enabled": item.desired_enabled,
            "declared_permissions": list(item.declared_permissions),
            "authorized_permissions": list(item.authorized_permissions),
            "provided_capabilities": list(item.provided_capabilities),
            "risk_tier": item.risk_tier,
            "last_error_type": error_type[:128],
        }

    def _require_plugin_operator(
        request: Request,
        payload: PluginActionPayload,
    ) -> dict[str, str]:
        """Bind high-risk plugin lifecycle actions to the console principal."""
        principal = get_request_principal(request)
        if bool(getattr(app.state, "nth_require_console_auth", False)):
            _require_console_principal(request)
        else:
            if principal.get("type") != "anonymous" or not bool(
                getattr(
                    app.state,
                    "nth_allow_unauthenticated_plugin_admin",
                    False,
                )
            ):
                raise HTTPException(
                    status_code=403,
                    detail="plugin administration requires the local console",
                )
            client_host = request.client.host if request.client is not None else ""
            if client_host != "testclient":
                try:
                    is_loopback = ipaddress.ip_address(client_host).is_loopback
                except ValueError:
                    is_loopback = False
                if not is_loopback:
                    raise HTTPException(
                        status_code=403,
                        detail="plugin administration requires a loopback client",
                    )
        _require_admin(state, payload.actor_id)
        principal_type = (
            "console"
            if principal.get("type") == "console"
            else "anonymous-local"
        )
        return {
            "principal_type": principal_type,
            "actor_id": payload.actor_id,
        }

    @app.post("/api/plugins/{plugin_id}/enable")
    def plugin_enable_endpoint(
        request: Request,
        plugin_id: str,
        payload: PluginActionPayload,
    ) -> dict[str, Any]:
        from nth_dao.plugins.builtin import FEDERATION_DISCOVERY_PLUGIN_ID
        from nth_dao.web import v2_api

        operator = _require_plugin_operator(request, payload)
        with state.plugin_lifecycle_lock:
            current = _plugin_status_or_404(plugin_id)
            is_federation = plugin_id == FEDERATION_DISCOVERY_PLUGIN_ID
            if is_federation:
                try:
                    v2_api.claim_market_federation_runtime_owner(app)
                except RuntimeError as exc:
                    raise HTTPException(
                        status_code=503,
                        detail="federation runtime is owned by another process",
                    ) from exc
            if current.state == "enabled":
                if is_federation:
                    try:
                        v2_api.activate_market_federation_plugin(app)
                    except (OSError, RuntimeError) as exc:
                        raise HTTPException(
                            status_code=503,
                            detail="federation plugin runtime activation failed",
                        ) from exc
                return {
                    "changed": False,
                    "plugin": _plugin_status_document(plugin_id),
                }
            try:
                state.plugin_host.authorize(
                    plugin_id,
                    set(current.declared_permissions),
                    operator=operator,
                )
                state.plugin_host.enable(plugin_id, operator=operator)
                if is_federation:
                    v2_api.activate_market_federation_plugin(app)
            except PluginAuthorizationError as exc:
                if is_federation:
                    v2_api.abandon_market_federation_runtime_owner(app)
                raise HTTPException(
                    status_code=403,
                    detail="plugin authorization denied",
                ) from exc
            except PluginAuditError as exc:
                if is_federation:
                    v2_api.abandon_market_federation_runtime_owner(app)
                raise HTTPException(
                    status_code=503,
                    detail="plugin audit commit failed",
                ) from exc
            except (PluginDependencyError, PluginLifecycleError) as exc:
                if is_federation:
                    v2_api.abandon_market_federation_runtime_owner(app)
                raise HTTPException(
                    status_code=409,
                    detail="plugin lifecycle transition rejected",
                ) from exc
            except (OSError, RuntimeError) as exc:
                if is_federation:
                    try:
                        state.plugin_host.disable(plugin_id, operator=operator)
                    except PluginLifecycleError:
                        logger.warning(
                            "federation plugin activation rollback failed",
                        )
                    try:
                        v2_api.suspend_market_federation_plugin(app)
                    except (OSError, RuntimeError):
                        logger.warning(
                            "federation runtime suspension persistence failed",
                        )
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "federation plugin runtime activation failed"
                        if is_federation
                        else "plugin runtime activation failed"
                    ),
                ) from exc
            return {
                "changed": True,
                "plugin": _plugin_status_document(plugin_id),
            }

    @app.post("/api/plugins/{plugin_id}/disable")
    def plugin_disable_endpoint(
        request: Request,
        plugin_id: str,
        payload: PluginActionPayload,
    ) -> dict[str, Any]:
        from nth_dao.plugins.builtin import FEDERATION_DISCOVERY_PLUGIN_ID
        from nth_dao.web import v2_api

        operator = _require_plugin_operator(request, payload)
        with state.plugin_lifecycle_lock:
            _plugin_status_or_404(plugin_id)
            is_federation = plugin_id == FEDERATION_DISCOVERY_PLUGIN_ID
            if is_federation:
                try:
                    v2_api.claim_market_federation_runtime_owner(app)
                except RuntimeError as exc:
                    raise HTTPException(
                        status_code=503,
                        detail="federation runtime is owned by another process",
                    ) from exc
            lifecycle_error = None
            try:
                changed = state.plugin_host.disable(plugin_id, operator=operator)
            except PluginDependencyError as exc:
                if is_federation:
                    v2_api.abandon_market_federation_runtime_owner(app)
                raise HTTPException(
                    status_code=409,
                    detail="plugin dependency prevents disable",
                ) from exc
            except PluginLifecycleError as exc:
                changed = False
                lifecycle_error = exc
            if is_federation:
                try:
                    stopped = v2_api.suspend_market_federation_plugin(app)
                except (OSError, RuntimeError) as exc:
                    raise HTTPException(
                        status_code=503,
                        detail=(
                            "federation plugin disabled but suspension was not persisted"
                        ),
                    ) from exc
                if not stopped:
                    raise HTTPException(
                        status_code=503,
                        detail=(
                            "federation plugin disabled but its poller is still stopping"
                        ),
                    )
            if lifecycle_error is not None:
                raise HTTPException(
                    status_code=409,
                    detail="plugin cleanup failed after routing was revoked",
                ) from lifecycle_error
            return {
                "changed": changed,
                "plugin": _plugin_status_document(plugin_id),
            }

    @app.post("/api/plugins/federation/refresh")
    def federation_plugin_refresh_endpoint(
        request: Request,
        payload: PluginActionPayload,
    ) -> dict[str, Any]:
        from nth_dao.plugins.builtin import (
            FEDERATION_DISCOVERY_CAPABILITY_ID,
            FEDERATION_DISCOVERY_PLUGIN_ID,
        )

        operator = _require_plugin_operator(request, payload)

        def record_refresh(error_type: str = "") -> None:
            try:
                state.plugin_host.record_refresh(
                    FEDERATION_DISCOVERY_PLUGIN_ID,
                    operator=operator,
                    error_type=error_type,
                )
            except PluginAuditError as exc:
                raise HTTPException(
                    status_code=503,
                    detail="plugin audit commit failed",
                ) from exc

        with state.plugin_lifecycle_lock:
            current = _plugin_status_or_404(FEDERATION_DISCOVERY_PLUGIN_ID)
            if current.state != "enabled":
                raise HTTPException(
                    status_code=409,
                    detail="federation plugin is not enabled",
                )
            try:
                binding = state.plugin_host.resolve_one(
                    FEDERATION_DISCOVERY_CAPABILITY_ID,
                )
                result = binding.invoke(
                    {},
                    authority=InvocationAuthority(
                        principal=f"local-operator:{payload.actor_id}",
                        capability_ids=frozenset(
                            {FEDERATION_DISCOVERY_CAPABILITY_ID}
                        ),
                    ),
                )
            except (PluginDependencyError, PluginInvocationError) as exc:
                record_refresh(type(exc).__name__)
                raise HTTPException(
                    status_code=409,
                    detail="federation capability is unavailable",
                ) from exc
            except PluginSchemaError as exc:
                record_refresh(type(exc).__name__)
                raise HTTPException(
                    status_code=502,
                    detail="plugin contract violation",
                ) from exc
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                record_refresh(type(exc).__name__)
                raise HTTPException(
                    status_code=503,
                    detail="federation refresh failed",
                ) from exc
            record_refresh()
            return {
                "refreshed": True,
                "result": result,
                "plugin": _plugin_status_document(FEDERATION_DISCOVERY_PLUGIN_ID),
            }

    @app.post("/api/plugins/registry/refresh")
    def curated_registry_plugin_refresh_endpoint(
        request: Request,
        payload: CuratedRegistryRefreshPayload,
    ) -> dict[str, Any]:
        from nth_dao.plugins.builtin import (
            CURATED_REGISTRY_CAPABILITY_ID,
            CURATED_REGISTRY_PLUGIN_ID,
        )

        operator = _require_plugin_operator(request, payload)

        if not state.curated_registry_refresh_lock.acquire(blocking=False):
            raise HTTPException(
                status_code=409,
                detail="curated registry refresh is already running",
            )
        try:
            with state.plugin_lifecycle_lock:
                current = _plugin_status_or_404(CURATED_REGISTRY_PLUGIN_ID)
                if current.state != "enabled":
                    raise HTTPException(
                        status_code=409,
                        detail="curated registry plugin is not enabled",
                    )
                binding = state.plugin_host.resolve_one(
                    CURATED_REGISTRY_CAPABILITY_ID,
                )
                refresh_limit = state.curated_registry_refresh_limiter.check(
                    f"{operator['principal_type']}:{operator['actor_id']}"
                )
                if not refresh_limit.allowed:
                    raise HTTPException(
                        status_code=429,
                        detail="curated registry refresh rate limit exceeded",
                        headers={
                            "Retry-After": str(
                                max(
                                    1,
                                    int(
                                        refresh_limit.retry_after_seconds + 0.999
                                    ),
                                )
                            )
                        },
                    )
            try:
                result = state.plugin_host.invoke_audited_refresh(
                    binding,
                    {"limit": payload.limit},
                    authority=InvocationAuthority(
                        principal=f"local-operator:{payload.actor_id}",
                        capability_ids=frozenset(
                            {CURATED_REGISTRY_CAPABILITY_ID}
                        ),
                    ),
                    operator=operator,
                )
            except PluginAuditError as exc:
                raise HTTPException(
                    status_code=503,
                    detail="plugin audit commit failed",
                ) from exc
            except (PluginDependencyError, PluginInvocationError) as exc:
                raise HTTPException(
                    status_code=409,
                    detail="curated registry capability is unavailable",
                ) from exc
            except PluginSchemaError as exc:
                raise HTTPException(
                    status_code=502,
                    detail="plugin contract violation",
                ) from exc
            except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail="curated registry refresh failed",
                ) from exc
            return {
                "refreshed": True,
                "result": result,
                "plugin": _plugin_status_document(CURATED_REGISTRY_PLUGIN_ID),
            }
        finally:
            state.curated_registry_refresh_lock.release()

    @app.post("/api/plugins/{plugin_id}/refreshes/{invocation_id}/abort")
    def plugin_refresh_abort_endpoint(
        request: Request,
        plugin_id: str,
        invocation_id: str,
        payload: PluginActionPayload,
    ) -> dict[str, Any]:
        """Reconcile one crash-left refresh without claiming it succeeded."""

        operator = _require_plugin_operator(request, payload)
        _plugin_status_or_404(plugin_id)
        try:
            state.plugin_host.abort_incomplete_refresh(
                plugin_id,
                invocation_id,
                operator=operator,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="refresh invocation id is invalid",
            ) from exc
        except PluginInvocationError as exc:
            raise HTTPException(
                status_code=409,
                detail="refresh intent is not pending",
            ) from exc
        except PluginLifecycleError as exc:
            raise HTTPException(
                status_code=409,
                detail="refresh invocation is still active",
            ) from exc
        except PluginAuditError as exc:
            raise HTTPException(
                status_code=503,
                detail="plugin audit commit failed",
            ) from exc
        return {
            "aborted": True,
            "invocation_id": invocation_id,
            "plugin": _plugin_status_document(plugin_id),
        }

    @app.get("/api/summary")
    def summary(actor_id: str = DEFAULT_ADMIN_ID) -> dict[str, Any]:
        config = state.membership.load_config()
        # Architect audit C-2 (2026-06-07): the original code returned
        # ``"workspace_is_local": True`` as a hard-coded constant, which
        # was technically true under the current in-process architecture
        # (the FastAPI app and the workspace files share one filesystem)
        # but read as a runtime detection. We now compute it honestly so
        # the flag remains correct if a future deployment ever runs the
        # web app pointing at a workspace it can't actually access (e.g.,
        # a stale symlink, an unmounted volume, a permission error).
        workspace_is_local = _workspace_is_locally_accessible(state.workspace)
        return {
            "team": _team_dict(config),
            "workspace": state.workspace.name or "local-workspace",
            "workspace_is_local": workspace_is_local,
            "members": len(config.member_ids),
            "channels": len(state.groups.list_channels(actor_id=DEFAULT_ADMIN_ID)),
            "tasks": len(state.groups.list_tasks()),
            "online_agents": len(state.registry.list_alive()),
            "active_missions": len(state.missions.list_active()),
            "blackboard_entries": len(state.blackboard.list()),
            "server_time": datetime.now().isoformat(),
            # R-35 (2026-06-08): when the caller is the bootstrap
            # admin (the common case for "Your code" in the dashboard
            # header), derive the code from the workspace's pubkey
            # so two installs show DIFFERENT codes. Pre-fix
            # ``code_for_agent_id("admin")`` produced ``8c69-76e5``
            # on every install in the world.
            "actor_code": _code_for_member(state, actor_id),
        }

    @app.get("/api/state")
    def dao_state(agent_id: str = DEFAULT_ADMIN_ID, channel_id: str = DEFAULT_CHANNEL_ID) -> dict[str, Any]:
        _require_member_or_joinable(state, agent_id)
        config = state.membership.load_config()
        return {
            "team": _team_dict(config),
            "actor": _actor_dict(agent_id, config.role_for(agent_id).value, state=state),
            "members": _members(state, config),
            "channels": [c.to_dict() for c in state.groups.list_channels(actor_id=agent_id)],
            "messages": [m.to_dict() for m in state.groups.list_messages(channel_id, actor_id=agent_id, limit=100)],
            "announcements": [a.to_dict() for a in state.groups.list_announcements(channel_id)],
            "tasks": [t.to_dict() for t in state.groups.list_tasks()],
            "audit": [e.to_dict() for e in state.groups.list_audit_events(limit=50)],
        }

    # v0.9.7: multi-DAO sidebar — one agent can hold many DAOs (home + groups).
    @app.get("/api/daos")
    def list_my_daos(actor_pubkey_hex: str = "", actor_id: str = DEFAULT_ADMIN_ID) -> dict[str, Any]:
        return {"daos": _list_my_daos(state, actor_pubkey_hex, actor_id)}

    @app.post("/api/daos/{slug}/channels")
    def dao_create_channel(slug: str, payload: ChannelPayload) -> dict[str, Any]:
        """Create a channel scoped to a DAO; channel_id auto-prefixed for groups."""
        kind, record = _resolve_dao(state, slug)
        _require_admin(state, payload.actor_id)
        prefix = _dao_channel_prefix(slug if kind == "group" else "")
        bare_id = payload.channel_id or payload.name or DEFAULT_CHANNEL_ID
        scoped_id = bare_id if bare_id.startswith(prefix) else f"{prefix}{bare_id}"
        channel = state.groups.create_channel(
            payload.name,
            created_by=payload.actor_id,
            topic=payload.topic,
            channel_id=scoped_id,
            is_private=payload.is_private,
            member_ids=payload.member_ids,
            metadata={
                "dao_id": slug if kind == "group" else HOME_DAO_SLUG,
                "dao_label": (
                    str(getattr(record, "display_name", "") or slug)
                    if kind == "group"
                    else "NTH DAO"
                ),
            },
        )
        return channel.to_dict()

    @app.post("/api/daos/{slug}/messages")
    def dao_post_message(slug: str, payload: MessagePayload) -> dict[str, Any]:
        kind, record = _resolve_dao(state, slug)
        _require_member(state, payload.agent_id)
        prefix = _dao_channel_prefix(slug if kind == "group" else "")
        channel_id = payload.channel_id or (prefix + "general" if prefix else DEFAULT_CHANNEL_ID)
        if prefix and not channel_id.startswith(prefix):
            raise HTTPException(status_code=400, detail=f"channel_id must start with '{prefix}' for DAO '{slug}'")
        msg = state.groups.post_message(channel_id, sender_id=payload.agent_id, body=payload.body)
        return msg.to_dict()

    @app.get("/api/daos/{slug}/state")
    def dao_scoped_state(
        slug: str,
        agent_id: str = DEFAULT_ADMIN_ID,
        channel_id: str = "",
    ) -> dict[str, Any]:
        kind, record = _resolve_dao(state, slug)
        # Default channel per DAO: legacy `general` for home, `dao-<slug>-general` for groups.
        prefix = _dao_channel_prefix(slug if kind == "group" else "")
        effective_channel = channel_id or (prefix + "general" if prefix else DEFAULT_CHANNEL_ID)

        _require_member_or_joinable(state, agent_id)
        config = state.membership.load_config()
        all_channels = state.groups.list_channels(actor_id=agent_id)
        scoped_channels = [
            c for c in all_channels if _dao_owns_channel(slug if kind == "group" else "", c.channel_id)
        ]
        scoped_announcements = [
            a for a in state.groups.list_announcements()
            if _dao_owns_channel(slug if kind == "group" else "", a.channel_id)
        ]
        scoped_tasks = [
            t for t in state.groups.list_tasks()
            if _dao_owns_channel(slug if kind == "group" else "", t.channel_id)
        ]
        # Members: home → workspace membership; group → pubkey set from GroupRecord.
        if kind == "home":
            members = _members(state, config)
        else:
            members = _members_from_group(record)  # type: ignore[arg-type]
        dao_meta = _dao_meta_dict(slug, kind, record, member_count=len(members))
        return {
            "team": _team_dict(config),
            "actor": _actor_dict(agent_id, config.role_for(agent_id).value, state=state),
            "dao": dao_meta,
            "members": members,
            "channels": [c.to_dict() for c in scoped_channels],
            "messages": [
                m.to_dict() for m in state.groups.list_messages(
                    effective_channel, actor_id=agent_id, limit=100,
                )
            ] if scoped_channels or kind == "home" else [],
            "announcements": [a.to_dict() for a in scoped_announcements],
            "tasks": [t.to_dict() for t in scoped_tasks],
            "audit": [e.to_dict() for e in state.groups.list_audit_events(limit=50)],
            "active_channel_id": effective_channel,
        }

    @app.post("/api/join")
    def join(payload: JoinPayload) -> dict[str, Any]:
        ok, reason = state.membership.ensure_member(payload.agent_id, token=payload.token)
        if not ok:
            raise HTTPException(status_code=403, detail=reason)
        return {"ok": True, "reason": reason, "agent_id": payload.agent_id}

    @app.post("/api/channels")
    def create_channel(payload: ChannelPayload) -> dict[str, Any]:
        _require_admin(state, payload.actor_id)
        channel = state.groups.create_channel(
            payload.name,
            created_by=payload.actor_id,
            topic=payload.topic,
            channel_id=payload.channel_id,
            is_private=payload.is_private,
            member_ids=payload.member_ids,
        )
        return channel.to_dict()

    @app.post("/api/messages")
    def post_message(payload: MessagePayload) -> dict[str, Any]:
        _require_member(state, payload.agent_id)
        msg = state.groups.post_message(
            payload.channel_id,
            sender_id=payload.agent_id,
            body=payload.body,
        )
        return msg.to_dict()

    @app.post("/api/announcements")
    def post_announcement(payload: AnnouncementPayload) -> dict[str, Any]:
        _require_permission(state, payload.author_id, "post_announcements")
        ann = state.groups.post_announcement(
            payload.title,
            payload.body,
            author_id=payload.author_id,
            channel_id=payload.channel_id,
        )
        return ann.to_dict()

    @app.post("/api/tasks")
    def create_task(payload: TaskPayload) -> dict[str, Any]:
        _require_member(state, payload.created_by)
        if payload.assignee_id:
            _require_member(state, payload.assignee_id)
        task = state.groups.create_task(
            payload.title,
            created_by=payload.created_by,
            description=payload.description,
            assignee_id=payload.assignee_id,
            channel_id=payload.channel_id,
            due_at=payload.due_at,
        )
        return task.to_dict()

    @app.patch("/api/tasks/{task_id}")
    def update_task(task_id: str, payload: TaskStatusPayload) -> dict[str, Any]:
        _require_member(state, payload.actor_id)
        try:
            TaskStatus(payload.status)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"invalid task status: {payload.status}") from exc
        try:
            task = state.groups.update_task_status(
                task_id,
                payload.status,
                actor_id=payload.actor_id,
                note=payload.note,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return task.to_dict()

    # v0.9.6: agent search + LAN discovery + add-friend

    @app.get("/api/agents/by_code/{code}")
    def lookup_agent_by_code(
        code: str,
        actor_id: str = "",
    ) -> dict[str, Any]:
        """Direct code lookup — the 'add by handle' analogue.

        Searches both home-workspace members (code derived from agent_id)
        and every GroupRegistry record's pubkey set (code derived from
        pubkey). Returns the first match; 404 if none.

        Architect R-13 (2026-06-07): the un-gated version of this
        endpoint was the smaller cousin of /api/agents/search - it
        returned a full group member's ``pubkey_hex`` to anyone who
        could guess a valid code. Mirrors C-1's fix: require actor_id,
        member-gate, redact pubkey for non-admins.
        """
        if not actor_id:
            raise HTTPException(
                status_code=400,
                detail="actor_id is required for by_code lookup",
            )
        _require_member(state, actor_id)
        actor_is_admin = state.membership.has_permission(
            actor_id, "manage_members",
        )
        try:
            normalized = parse_code(code)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # 1) Try home members.
        # R-48 (2026-06-08): one helper call gives us (code, pubkey, contact)
        # in a single ContactBook hit, removing the separate
        # ``resolved_pk`` resolution that used to lag behind the code
        # derivation (and could diverge on a future refactor).
        config = state.membership.load_config()
        for agent_id in config.member_ids:
            member_code, resolved_pk, _contact = _resolve_member_identity(
                state, agent_id,
            )
            # R-46: empty code means "no crypto material" - skip such
            # rows in by_code lookup because they can never be matched
            # by a real handle anyway.
            if not member_code:
                continue
            if member_code.replace("-", "") == normalized:
                return {
                    "code": member_code,
                    "agent_id": agent_id,
                    # Honour the C-1 redaction posture: non-admins get
                    # the prefix only, even when the home member is
                    # this node's own owner.
                    "pubkey_hex": (
                        resolved_pk if actor_is_admin else ""
                    ),
                    "pubkey_prefix": resolved_pk[:16],
                    "source": "home",
                    "role": config.role_for(agent_id).value,
                }
        # 2) Try every group's pubkey set.
        for record in state.group_registry.list_all():
            for pk in set(record.member_pubkeys + record.admin_pubkeys):
                if code_for_pubkey(pk).replace("-", "") == normalized:
                    payload: dict[str, Any] = {
                        "code": code_for_pubkey(pk),
                        "agent_id": pk[:16],
                        "source": "group",
                        "group_slug": record.slug,
                        "role": "admin" if pk in record.admin_pubkeys else "member",
                        "pubkey_prefix": pk[:16],
                    }
                    if actor_is_admin:
                        payload["pubkey_hex"] = pk
                    else:
                        # Empty string preserves the legacy shape ("the
                        # field is present, value is masked") without
                        # leaking the real key to non-admins.
                        payload["pubkey_hex"] = ""
                    return payload
        raise HTTPException(status_code=404, detail=f"agent code '{code}' not found")

    @app.get("/api/agents/search")
    def search_agents(
        q: str = "",
        limit: int = 10,
        actor_id: str = "",
    ) -> dict[str, Any]:
        """consumer chat app-inspired fuzzy search across known agents.

        Searches the live registry first, then local team members and group
        pubkey members. PR #10 only searched ``team_agents`` records, so a
        normal local workspace with members but no live daemons produced an
        empty UI. This endpoint is for finding people, not only online peers.

        Architect audit C-1 (2026-06-07): the original endpoint required
        no authentication and exposed every member's role plus every
        group member's full ``pubkey_hex``. That let any caller (LAN
        peer / mis-bound public listener) enumerate the full social graph.
        Now requires ``actor_id`` AND restricts the response:

          * non-members get 403 (same gate as the rest of the console)
          * full ``pubkey_hex`` is only shown to callers with the
            ``manage_members`` permission (admins). Everyone else sees
            a prefix-truncated ``pubkey_prefix`` so the ``code`` lookup
            still works without leaking the full key
        """
        if not actor_id:
            raise HTTPException(
                status_code=400,
                detail="actor_id is required for agent search",
            )
        _require_member(state, actor_id)
        actor_is_admin = state.membership.has_permission(
            actor_id, "manage_members",
        )

        # M-1 fix: clamp `limit` defensively so `?limit=foo` becomes a
        # 400, not a 500 from the unhandled ValueError in int().
        try:
            limit_int = int(limit)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"limit must be an integer: {exc}",
            ) from exc
        max_results = min(max(limit_int, 1), 50)

        if not q.strip():
            return {"query": q, "results": []}
        # H-4 fix: dedup key is now (source, identifier) - prevents an
        # `agent_id` collision with a 16-char pubkey prefix from silently
        # dropping one of the two rows.
        results_by_key: dict[tuple[str, str], dict[str, Any]] = {}

        def add_result(row: dict[str, Any]) -> None:
            agent_id = str(row.get("agent_id", ""))
            if not agent_id:
                return
            key = (str(row.get("source", "")), agent_id)
            previous = results_by_key.get(key)
            if previous is None or float(row.get("score", 0)) > float(previous.get("score", 0)):
                results_by_key[key] = row

        for r in state.peer_finder.search(q, limit=max_results, only_alive=False):
            # DID persistence (2026-06-08): registry rows also carry
            # DID. Two sources, in priority order:
            #   1. AgentRecord.metadata explicitly populates "did" /
            #      "pubkey_hex" when an agent self-registers with
            #      crypto material (the LAN mDNS / UDP path does this).
            #   2. ContactBook fallback by agent_id - covers the case
            #      where we added the agent by DID earlier but the
            #      live registry record was published by a daemon
            #      that didn't know about the DID flow.
            metadata = r.record.metadata or {}
            registry_did = str(metadata.get("did", "") or "")
            registry_pk = str(metadata.get("pubkey_hex", "") or "")
            if not registry_did or not registry_pk:
                try:
                    contact = state.contacts.get(r.record.agent_id)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "contact_book lookup failed for registry row %s: %s",
                        r.record.agent_id,
                        exc,
                    )
                    contact = None
                if contact is not None:
                    registry_did = registry_did or contact.did
                    registry_pk = registry_pk or contact.pubkey_hex
            # R-57 (2026-06-08): when a pubkey is known for this
            # registry row (from AgentRecord.metadata or the
            # ContactBook fallback above), prefer the pubkey-derived
            # code. Falling back to ``code_for_agent_id`` for LAN
            # daemons that all use the default agent_id="admin" would
            # make every remote node's code collapse to ``8c69-76e5``.
            #
            # A-5 (2026-06-08, architect review): if the row carries
            # ``did`` but no ``pubkey_hex``, decode the did:key to
            # recover the pubkey before deriving the code. Without
            # this, a peer that publishes DID-only (e.g. a future
            # protocol revision or a minimal third-party node) would
            # fall through to ``code_for_agent_id`` and reintroduce
            # the R-35 collision. ``_resolve_member_identity`` already
            # does this for ContactBook contacts; mirror that here.
            if not registry_pk and registry_did:
                try:
                    if is_did_key(registry_did):
                        registry_pk = decode_ed25519_did_key_hex(
                            registry_did,
                        ) or ""
                except Exception:  # noqa: BLE001
                    pass
            registry_code = (
                code_for_pubkey(registry_pk)
                if registry_pk
                else code_for_agent_id(r.record.agent_id)
            )
            row = {
                "agent_id": r.record.agent_id,
                "score": r.score,
                "status": r.record.status if r.record.is_alive() else "offline",
                "hostname": r.record.hostname,
                "backend_id": r.record.backend_id,
                "capabilities": list(r.record.capabilities),
                "groups": list(r.record.groups),
                "last_seen": r.record.last_seen,
                "matched": list(r.matched_capabilities),
                "code": registry_code,
                "source": "registry",
                "role": "",
                "did": registry_did,
                "pubkey_prefix": registry_pk[:16] if registry_pk else "",
            }
            if actor_is_admin and registry_pk:
                row["pubkey_hex"] = registry_pk
            add_result(row)

        config = state.membership.load_config()
        online_records = {r.agent_id: r for r in state.registry.list_alive()}
        # DID bootstrap (2026-06-07) + DID persistence (2026-06-08):
        # home-row DID enrichment now uses TWO sources:
        #
        #   1. ``state.node_identity`` is THIS workspace's own DID -
        #      surfaces on the bootstrap admin row so the operator and
        #      any peer learn "that's this node here".
        #   2. ``state.contacts`` (ContactBook) is the per-member DID
        #      we learned via ``/api/agents/add(target_did=...)`` or
        #      other discovery paths. Surfaces on EVERY home row that
        #      has a record - so after Bob restarts, the row for
        #      Alice still carries her DID even though Alice's DID
        #      lives in HER workspace, not Bob's identity.json.
        #
        # node_identity wins ties for the admin row (it's authoritative
        # for "this workspace's owner"); ContactBook fills in everyone
        # else. Both paths emit "" for unknown to keep the front-end
        # truth-value check (`row.did || fallback`) honest.
        node_did = _safe_did(state.node_identity)
        for agent_id in config.member_ids:
            # R-37 (2026-06-08): pubkey-derived code when we have one
            # (admin via node_identity, others via ContactBook), so
            # two installs that both happen to add an agent named
            # "admin" still distinguish them by Ed25519 fingerprint.
            # R-51 (2026-06-08): one helper call returns (code, pubkey,
            # contact), so the row enrichment below does NOT re-query
            # ContactBook a second time.
            code, member_pk, contact = _resolve_member_identity(
                state, agent_id,
            )
            role = config.role_for(agent_id).value
            score, matched = _score_contact_query(
                q, [agent_id, code, role, "home"],
            )
            if score <= 0:
                continue
            live = online_records.get(agent_id)
            row = {
                "agent_id": agent_id,
                "score": score,
                "status": live.status if live else "offline",
                "hostname": live.hostname if live else "",
                "backend_id": live.backend_id if live else "",
                "capabilities": list(live.capabilities) if live else [],
                "groups": list(live.groups) if live else ["home"],
                "last_seen": live.last_seen if live else "",
                "matched": matched,
                "code": code,
                "source": "home",
                "role": role,
                "did": "",
                "pubkey_prefix": "",
            }
            # 1) bootstrap admin row also picks up the node's did:key.
            # The helper already gave us the pubkey from node_identity
            # so we only need the did here.
            if agent_id == DEFAULT_ADMIN_ID and node_did:
                row["did"] = node_did
            # 2) Pubkey-prefix comes from whatever the helper resolved.
            #    Honour the C-1 redaction posture for non-admins.
            if member_pk:
                row["pubkey_prefix"] = member_pk[:16]
                if actor_is_admin:
                    row["pubkey_hex"] = member_pk
            # 3) Pick up did + label from the contact record we
            #    already have - no second ContactBook query.
            if contact is not None:
                if not row["did"] and contact.did:
                    row["did"] = contact.did
                if contact.label and not row.get("label"):
                    row["label"] = contact.label
            add_result(row)

        # Architect R-4 (2026-06-07): the endorsement count + group
        # list scans are now cached by file mtime. On the steady-state
        # dashboard-polling case (5 s interval, files unchanged) we
        # serve search from in-memory dicts. When the underlying file
        # changes, the next call recomputes once.
        def _compute_endorsement_counts() -> dict[str, int]:
            try:
                _all = state.trust.list_endorsements()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "WoT endorsement load failed; serving 0 counts: %s",
                    exc,
                )
                return {}
            counts: dict[str, int] = {}
            for e in _all:
                counts[e.subject_pubkey] = counts.get(e.subject_pubkey, 0) + 1
            return counts

        endorsement_count_by_pk = state._endorsement_count_cache.get(
            probe_paths=[
                state.trust._endorsements_path,
                state.trust._revocations_path,
            ],
            compute=_compute_endorsement_counts,
        )

        # Cache the deserialised group records too - GroupRegistry.list_all()
        # globs the directory and JSON-parses every file per call.
        def _compute_group_list():
            return state.group_registry.list_all()

        group_records = state._group_list_cache.get(
            probe_paths=list(state.group_registry.base.glob("*.json"))
            + [state.group_registry.base],
            compute=_compute_group_list,
        )
        for record in group_records:
            admin_set = {p.lower() for p in record.admin_pubkeys}
            for pk in sorted(set(record.member_pubkeys + record.admin_pubkeys)):
                code = code_for_pubkey(pk)
                role = "admin" if pk.lower() in admin_set else "member"
                display_id = pk[:16]
                score, matched = _score_contact_query(
                    q, [display_id, code, role, record.slug, record.display_name],
                )
                if score <= 0:
                    continue
                row = {
                    "agent_id": display_id,
                    "score": score,
                    "status": "offline",
                    "hostname": "",
                    "backend_id": "",
                    "capabilities": [],
                    "groups": [record.slug],
                    "last_seen": "",
                    "matched": matched,
                    "code": code,
                    "source": "group",
                    "role": role,
                    "group_slug": record.slug,
                    # Architect C-1: redact pubkey for non-admin callers.
                    # The truncated prefix is still useful for the
                    # `code` lookup the dashboard does on click.
                    "pubkey_prefix": pk[:16],
                    # Week-1 Task 4: surface the WoT endorsement count
                    # so the dashboard can show "12 endorsements" badges
                    # without needing a separate WoT query per row.
                    "endorsement_count": endorsement_count_by_pk.get(pk, 0),
                }
                if actor_is_admin:
                    row["pubkey_hex"] = pk
                add_result(row)

        rows = sorted(
            results_by_key.values(),
            key=lambda row: float(row.get("score", 0)),
            reverse=True,
        )[:max_results]
        return {
            "query": q,
            "results": rows,
        }

    @app.post("/api/v2/agents/lan_discover")
    @app.post("/api/agents/lan_discover")
    def lan_discover(payload: LANDiscoverPayload) -> dict[str, Any]:
        """Active "people nearby" via UDP broadcast on the LAN.

        Architect R-5 (2026-06-07):
          * actor_id is required and gated through _require_member
          * the requesting actor_id is used to identify the querier
            on the LAN (NOT a hard-coded DEFAULT_ADMIN_ID), so the
            broadcast can no longer impersonate the admin
          * PSK comes from NTH_DISCOVERY_PSK env var, never from the
            request payload, closing the "probe PSKs one at a time"
            channel
          * a per-actor rate limit caps how often a caller can trigger
            UDP broadcasts (cheap-request, expensive-response is an
            amplification pattern we must not let through)
        """
        if not payload.actor_id:
            raise HTTPException(
                status_code=400,
                detail="actor_id is required for lan_discover",
            )
        _require_member(state, payload.actor_id)

        decision = _lan_discover_limiter.check(payload.actor_id)
        if not decision.allowed:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"lan_discover rate limit exceeded; retry after "
                    f"{decision.retry_after_seconds:.1f}s"
                ),
            )

        server_psk = os.environ.get("NTH_DISCOVERY_PSK", "").strip()
        # LAN DID publish (2026-06-07): the querier ALSO advertises its
        # DID in the request, so a remote responder can know "this
        # request came from did:key:zXYZ" and decide whether to reply.
        # (For now responders accept all queries; the field is in place
        # for a future trust-graph-gated discovery mode.)
        querier_did = _safe_did(state.node_identity)
        querier_pk = (
            getattr(state.node_identity, "pubkey_hex", "")
            if state.node_identity is not None else ""
        ) or ""
        querier = LANDiscovery(
            agent_id=payload.actor_id,
            psk=server_psk,
            pubkey_hex=querier_pk,
            did=querier_did,
        )
        peers = querier.discover(
            timeout=min(max(0.5, payload.timeout_seconds), 6.0),
            wanted_capabilities=payload.wanted_capabilities or None,
        )

        def _peer_federation_url(peer: Any) -> str:
            metadata = getattr(peer, "metadata", {}) or {}
            if isinstance(metadata, dict):
                for key in ("federation_url", "http_url", "api_url", "base_url"):
                    cleaned = _clean_public_base_url(str(metadata.get(key, "")))
                    if cleaned:
                        return cleaned
            return _clean_public_base_url(getattr(peer, "ws_url", "") or "")

        # LAN DID publish: surface each peer's did:key + a stable
        # 16-hex pubkey_prefix to the caller so the dashboard can
        # render "found DID X" without an extra fetch.
        return {
            "peers": [
                {
                    "agent_id": p.agent_id,
                    "label": p.label,
                    "capabilities": list(p.capabilities),
                    "groups": list(p.groups),
                    "ws_url": p.ws_url,
                    "pubkey_hex": p.pubkey_hex,
                    "pubkey_prefix": (p.pubkey_hex or "")[:16],
                    "did": getattr(p, "did", "") or "",
                    "source_addr": p.source_addr,
                    "rtt_ms": p.rtt_ms,
                    "metadata": dict(getattr(p, "metadata", {}) or {}),
                    "federation_peer_url": _peer_federation_url(p),
                }
                for p in peers
            ],
        }

    @app.post("/api/v2/agents/add")
    @app.post("/api/agents/add")
    def add_agent(payload: AddAgentPayload) -> dict[str, Any]:
        """Add a known agent as a member of the local team.

        Accepts agent_id (legacy) OR did:key (W3C). Resolution rules:
            - If did, extract the pubkey via decode_ed25519_did_key, derive
              fingerprint-style agent_id.
            - If agent_id given directly, use it as-is.
        Subject to membership policy: the team's join_policy still applies.

        DID persistence (2026-06-08): on successful add, the supplied
        ``target_did`` (if any) and the derived ``pubkey_hex`` are
        written to the workspace's ``ContactBook`` so the DID survives
        process restarts. Without this, a search row for the added
        agent on the next boot would carry ``did=""`` and the operator
        could no longer reach them by DID.
        """
        _require_admin(state, payload.actor_id)
        target_id = payload.target_agent_id.strip()
        derived_pubkey_hex = ""
        if payload.target_did:
            # R-58: did_key helpers are imported at module scope.
            if not is_did_key(payload.target_did):
                raise HTTPException(status_code=400, detail="invalid did:key")
            derived_pubkey_hex = decode_ed25519_did_key_hex(payload.target_did)
            target_id = target_id or str(AgentID.from_pubkey(derived_pubkey_hex))
        if not target_id:
            raise HTTPException(status_code=400, detail="target_agent_id or target_did required")
        try:
            ok, reason = state.membership.ensure_member(target_id)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not ok:
            raise HTTPException(status_code=403, detail=reason)

        # DID persistence: write to the contact book AFTER membership
        # gate accepts. We do this best-effort - the membership change
        # is already durable, so a contact book write failure should
        # not roll back the visible "added" state. We surface it via
        # logger.warning so an operator can investigate.
        try:
            state.contacts.add(
                agent_id=target_id,
                did=payload.target_did or "",
                pubkey_hex=derived_pubkey_hex,
                label=payload.label or "",
                source=CONTACT_SOURCE_MANUAL,
                added_by=payload.actor_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "contact_book write failed for agent_id=%s (membership "
                "still applied; DID will not appear in search until "
                "the row is re-added or repaired): %s",
                target_id, exc,
            )
            if payload.target_did:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "agent membership was added, but DID contact "
                        "persistence failed; re-add after repairing the "
                        "contact book"
                    ),
                ) from exc
        return {
            "ok": True,
            "agent_id": target_id,
            "did": payload.target_did or "",
            "label": payload.label,
        }

    # v0.9.6: group registry CRUD + search
    @app.post("/api/groups/registry")
    def create_unique_group(payload: GroupCreatePayload) -> dict[str, Any]:
        """Create a workspace-unique group. Display name must produce a unique slug."""
        _require_admin(state, payload.actor_id)
        # We can't sign without a private key on the server, so instead we
        # produce the unsigned spec and let the caller pass back a signed
        # record. For the common case we accept a server-side surrogate sign:
        # the founder's pubkey AND signature are echoed back in the response
        # so the TS client can attach them after a wallet signs.
        from nth_dao.group_registry import normalize_group_name, GroupRecord, GroupPolicy
        try:
            slug = normalize_group_name(payload.display_name)
        except GroupRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Reject if slug already taken (without writing anything).
        existing = state.group_registry.load_by_slug(slug)
        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail=f"slug '{slug}' already taken by group {existing.group_id}",
            )
        try:
            policy = GroupPolicy(payload.policy)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"unknown policy {payload.policy!r}") from exc
        # Pre-construct the record; caller (TS) signs and posts back.
        record = GroupRecord(
            group_id="",
            slug=slug,
            display_name=payload.display_name,
            description=payload.description,
            policy=policy,
            founder_pubkey=payload.actor_pubkey_hex,
            member_pubkeys=[payload.actor_pubkey_hex],
            admin_pubkeys=[payload.actor_pubkey_hex],
            signer_pubkey=payload.actor_pubkey_hex,
        )
        return {
            "slug": slug,
            "unsigned_record": record.to_dict(),
            "to_sign": record.signable_dict(),
            "next": "POST /api/groups/registry/publish with proof_id, sig",
        }

    @app.post("/api/groups/registry/publish")
    def publish_group(payload: GroupPublishPayload) -> dict[str, Any]:
        """Persist a signed GroupRecord. Signature must verify; slug must be free."""
        from nth_dao.group_registry import GroupRecord

        try:
            record = GroupRecord.from_dict(payload.record)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"invalid record: {exc}") from exc
        if not record.group_id:
            raise HTTPException(status_code=400, detail="group_id must be signed by the client")
        try:
            state.group_registry.publish(record)
        except GroupRegistryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return record.to_dict()

    @app.get("/api/groups/registry")
    def list_unique_groups() -> dict[str, Any]:
        return {
            "groups": [r.to_dict() for r in state.group_registry.list_all()],
            "index": state.group_registry.load_index(),
        }

    @app.post("/api/groups/registry/search")
    def search_groups(payload: GroupSearchPayload) -> dict[str, Any]:
        from nth_dao.group_registry import GroupPolicy

        policy = None
        if payload.policy:
            try:
                policy = GroupPolicy(payload.policy)
            except ValueError:
                pass
        results = state.group_registry.search(payload.query, limit=payload.limit, policy=policy)
        return {"query": payload.query, "results": [r.to_dict() for r in results]}

    # v0.9.6: group governance via signed votes

    @app.post("/api/groups/registry/{group_id}/proposals")
    def create_proposal(group_id: str, payload: PolicyProposalPayload) -> dict[str, Any]:
        """Build an unsigned policy-change proposal for the caller (TS) to sign."""
        group = state.group_registry.load_by_id(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="group not found")
        if payload.actor_pubkey_hex not in group.member_pubkeys:
            raise HTTPException(status_code=403, detail="only members can propose")
        # Build an unsigned skeleton. TS signs and posts via /publish below.
        try:
            new_policy = GroupPolicy(payload.new_policy) if payload.new_policy else group.policy
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"unknown policy {payload.new_policy!r}") from exc
        skeleton = PolicyChangeProposal(
            proposal_id=uuid.uuid4().hex[:12],
            group_id=group.group_id,
            proposer_pubkey=payload.actor_pubkey_hex,
            proposed_policy=new_policy,
            proposed_add_members=list(payload.add_member_pubkeys),
            proposed_remove_members=list(payload.remove_member_pubkeys),
            proposed_display_name=payload.new_display_name,
            rationale=payload.rationale,
            expires_at=(datetime.now() + timedelta(days=max(1, payload.ttl_days))).isoformat(),
        )
        return {
            "unsigned_proposal": skeleton.to_dict(),
            "to_sign": skeleton.signable_dict(),
            "next": "POST /api/groups/registry/{group_id}/proposals/publish with sig",
        }

    @app.post("/api/groups/registry/{group_id}/proposals/publish")
    def publish_proposal(group_id: str, payload: ProposalPublishPayload) -> dict[str, Any]:
        try:
            proposal = PolicyChangeProposal.from_dict(payload.proposal)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"invalid proposal: {exc}") from exc
        if proposal.group_id != group_id:
            raise HTTPException(status_code=400, detail="proposal/group_id mismatch")
        group = state.group_registry.load_by_id(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="group not found")
        if proposal.proposer_pubkey not in group.member_pubkeys:
            raise HTTPException(status_code=403, detail="only members can propose")
        if not proposal.verify_proposer_signature():
            raise HTTPException(status_code=400, detail="proposer signature invalid")
        state.group_registry.save_proposal(proposal)
        return proposal.to_dict()

    @app.get("/api/groups/registry/{group_id}/proposals")
    def list_proposals(group_id: str) -> dict[str, Any]:
        group = state.group_registry.load_by_id(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="group not found")
        proposals = []
        for p in state.group_registry.list_proposals_for(group_id):
            passed, reason = resolve_proposal(p, group)
            d = p.to_dict()
            d["resolved"] = {"passed": passed, "reason": reason}
            proposals.append(d)
        return {"group_id": group_id, "proposals": proposals}

    @app.post("/api/groups/registry/{group_id}/proposals/{proposal_id}/vote")
    def add_vote(group_id: str, proposal_id: str, payload: VoteCastPayload) -> dict[str, Any]:
        """Build an unsigned vote payload for the client to sign."""
        proposal = state.group_registry.load_proposal(proposal_id)
        if proposal is None or proposal.group_id != group_id:
            raise HTTPException(status_code=404, detail="proposal not found")
        group = state.group_registry.load_by_id(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="group not found")
        if payload.voter_pubkey_hex not in group.member_pubkeys:
            raise HTTPException(status_code=403, detail="only members can vote")
        if payload.choice not in ("yes", "no", "abstain"):
            raise HTTPException(status_code=400, detail="choice must be yes/no/abstain")
        voted_at = datetime.now().isoformat()
        unsigned_vote = {
            "voter_pubkey": payload.voter_pubkey_hex,
            "choice": payload.choice,
            "voted_at": voted_at,
            "sig": "",
        }
        return {
            "unsigned_vote": unsigned_vote,
            "to_sign": {
                "proposal_id": proposal.proposal_id,
                "choice": payload.choice,
                "voted_at": voted_at,
            },
        }

    @app.post("/api/groups/registry/{group_id}/proposals/{proposal_id}/sign_vote")
    def add_signed_vote(group_id: str, proposal_id: str, payload: SignedVotePayload) -> dict[str, Any]:
        proposal = state.group_registry.load_proposal(proposal_id)
        if proposal is None or proposal.group_id != group_id:
            raise HTTPException(status_code=404, detail="proposal not found")
        group = state.group_registry.load_by_id(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="group not found")
        ok, reason = proposal.validate_vote(payload.vote, group.member_pubkeys)
        if not ok:
            raise HTTPException(status_code=400, detail=reason)
        voter = payload.vote.get("voter_pubkey", "")
        proposal.votes = [vote for vote in proposal.votes if vote.get("voter_pubkey") != voter]
        proposal.votes.append(payload.vote)
        state.group_registry.save_proposal(proposal)
        passed, reason = resolve_proposal(proposal, group)
        return {
            "proposal": proposal.to_dict(),
            "resolved": {"passed": passed, "reason": reason},
        }

    # v0.10 T-9: Mandate sidebar - read-only listings + verify + store
    #
    # Voss V-28: every mandate route runs through the same membership
    # gate as the rest of the web console. Mandates leak counterparty
    # / amount / settlement-rail metadata; an anonymous reader is not
    # an acceptable default even for local-first deployments.
    @app.get("/api/mandates")
    def list_mandates(actor_id: str) -> dict[str, Any]:
        """List all mandates with summary rows for the sidebar."""
        _require_explicit_actor_id(actor_id)
        _require_member(state, actor_id)
        return {
            "intents": [_summarise_intent(m) for m in state.mandates.list_intents()],
            "carts": [_summarise_cart(m) for m in state.mandates.list_carts()],
            "payments": [
                _summarise_payment(m) for m in state.mandates.list_payments()
            ],
        }

    @app.get("/api/mandates/{kind}/{digest}")
    def get_mandate(
        kind: str, digest: str, actor_id: str,
    ) -> Response:
        """Return the full mandate body for a digest.

        Voss V-48: a mandate body is content-addressed by its digest
        and never changes (re-saving the same digest is a no-op per
        V-36). Serving with ``Cache-Control: public, immutable``
        lets the browser skip the re-fetch entirely on the sidebar's
        next render.
        """
        _require_explicit_actor_id(actor_id)
        _require_member(state, actor_id)
        if kind not in MANDATE_KINDS:
            raise HTTPException(status_code=400, detail=f"unknown kind: {kind!r}")
        try:
            body = state.mandates.get(kind, digest)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if body is None:
            raise HTTPException(status_code=404, detail="mandate not found")
        # F-1 (4th-round audit): "private" not "public" - a mandate
        # body carries counterparty DIDs, amounts, and settlement
        # rail. ``public`` would let shared proxies (corp HTTP
        # proxy, ISP cache, CDN) hold the bytes for 24h, defeating
        # V-28 auth gating entirely. ``private`` means only the end
        # browser's own cache stores it.
        return JSONResponse(
            body,
            headers={
                "Cache-Control": "private, max-age=86400, immutable",
                "ETag": f'"{digest}"',
            },
        )

    @app.post("/api/mandates/store")
    async def store_mandate(payload: MandateStorePayload) -> dict[str, Any]:
        """Persist a signed mandate; returns the canonical digest.

        Server re-derives the digest from the body so the index
        filename is authoritative. Callers cannot pin a wrong digest.

        Shape-checks the body before saving so a junk payload doesn't
        produce a worthless hash file on disk: the W3C VC ``type``
        array must contain the expected mandate type for the kind.

        Voss F-5: store has the same 50ms response-time floor as
        verify, including 403 / 429 / malformed-body paths. Store runs
        signature verification before persistence, so leaving it as a
        fast-fail endpoint recreates the timing oracle that verify
        already closed.
        """
        import time as _time

        _start = _time.monotonic()
        try:
            return await _store_mandate_body(payload, state, _start)
        except HTTPException:
            await enforce_min_response_time(_start, 0.05)
            raise
    async def _store_mandate_body(
        payload: MandateStorePayload,
        state: WebState,
        _start: float,
    ) -> dict[str, Any]:
        _require_explicit_actor_id(payload.actor_id)
        _require_member(state, payload.actor_id)
        # V-30: rate limit the store endpoint too - it runs a full
        # signature verification before persisting (V-29).
        store_decision = state.store_limiter.check(payload.actor_id or "anonymous")
        if not store_decision.allowed:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"store rate limit exceeded; retry after "
                    f"{store_decision.retry_after_seconds:.1f}s"
                ),
                headers={"Retry-After": f"{int(store_decision.retry_after_seconds) + 1}"},
            )
        kind = payload.kind
        if kind not in MANDATE_KINDS:
            raise HTTPException(status_code=400, detail=f"unknown kind: {kind!r}")
        body = payload.mandate
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="mandate must be a JSON object")
        if not _looks_like_mandate(kind, body):
            raise HTTPException(
                status_code=400,
                detail=f"body does not look like a {kind} mandate "
                "(missing @context / type / credentialSubject)",
            )
        # Voss V-29: refuse to store unsigned / invalidly-signed
        # mandates. Without this gate any client can pollute the
        # sidebar with mandates that no party actually signed.
        try:
            if kind == KIND_INTENT:
                sig_ok, sig_reason = verify_intent_mandate(body)
            elif kind == KIND_CART:
                sig_ok, sig_reason = verify_cart_mandate(body)
            else:
                sig_ok, sig_reason = verify_payment_mandate(body)
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(
                status_code=400, detail=f"malformed {kind}: {exc}",
            ) from exc
        if not sig_ok:
            raise HTTPException(
                status_code=400,
                detail=f"refusing to store {kind} with invalid signature: {sig_reason}",
            )
        try:
            if kind == KIND_INTENT:
                digest = state.mandates.save_intent(body)
            elif kind == KIND_CART:
                digest = state.mandates.save_cart(body)
            else:
                digest = state.mandates.save_payment(body)
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid {kind}: {exc}") from exc
        await enforce_min_response_time(_start, 0.05)
        return {"ok": True, "kind": kind, "digest": digest}

    @app.post("/api/mandates/verify")
    async def verify_mandate_route(payload: MandateVerifyPayload) -> dict[str, Any]:
        """Verify signature and (optionally) binding constraints.

        The sidebar's per-row [Verify] button calls this for a quick
        green/red badge; adapters call it before settlement. The
        binding fields (``against_intent`` / ``against_cart``) extend
        the check upward through the triad without forcing a separate
        round-trip per layer.

        Voss V-30 + follow-up timing tightening:

          * Per-actor sliding-window rate limit (30/min by default)
            caps the DoS / oracle exposure.
          * A 50ms response-time floor applies to EVERY return path
            including HTTPException raisings (403 / 429 / 400). The
            outer try/except below catches HTTPException so the
            floor runs before the exception propagates - without
            this, a 403 (non-member) returns in <1ms while a 200
            takes 50ms, leaking membership status via wall-clock.
        """
        import time as _time

        _start = _time.monotonic()
        try:
            return await _verify_mandate_body(payload, state, _start)
        except HTTPException:
            # Pad the error path too so 403 / 429 / 400 don't leak
            # gate identity via latency.
            await enforce_min_response_time(_start, 0.05)
            raise

    async def _verify_mandate_body(
        payload: MandateVerifyPayload,
        state: WebState,
        _start: float,
    ) -> dict[str, Any]:
        _require_explicit_actor_id(payload.actor_id)
        _require_member(state, payload.actor_id)
        decision = state.verify_limiter.check(payload.actor_id or "anonymous")
        if not decision.allowed:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"verify rate limit exceeded; retry after "
                    f"{decision.retry_after_seconds:.1f}s"
                ),
                headers={"Retry-After": f"{int(decision.retry_after_seconds) + 1}"},
            )
        kind = payload.kind
        if kind not in MANDATE_KINDS:
            await enforce_min_response_time(_start, 0.05)
            raise HTTPException(status_code=400, detail=f"unknown kind: {kind!r}")
        body = payload.mandate
        if not isinstance(body, dict):
            await enforce_min_response_time(_start, 0.05)
            raise HTTPException(status_code=400, detail="mandate must be a JSON object")

        # Reject obviously-non-mandate shapes early so the verify
        # tuple's "missing proof" branch doesn't get reported as a
        # signature failure. Without this gate, ``{"junk": True}``
        # would render as a generic signature error which is less
        # useful in the UI than a clear "malformed" badge.
        if not _looks_like_mandate(kind, body):
            await enforce_min_response_time(_start, 0.05)
            return {"ok": False, "reason": f"malformed {kind}: not a W3C VC body"}
        # Layer 1: signature verification.
        # The mandate.verify_*_mandate helpers return (ok, reason)
        # tuples, NOT bare booleans - unpacking them avoids the trap
        # where a truthy tuple gets treated as success.
        try:
            if kind == KIND_INTENT:
                sig_ok, sig_reason = verify_intent_mandate(body)
                expired = is_intent_expired(body)
            elif kind == KIND_CART:
                sig_ok, sig_reason = verify_cart_mandate(body)
                expired = is_cart_expired(body)
            else:
                sig_ok, sig_reason = verify_payment_mandate(body)
                expired = is_payment_expired(body)
        except (ValueError, KeyError, TypeError) as exc:
            await enforce_min_response_time(_start, 0.05)
            return {"ok": False, "reason": f"malformed {kind}: {exc}"}

        if not sig_ok:
            await enforce_min_response_time(_start, 0.05)
            return {
                "ok": False,
                "reason": f"signature verification failed: {sig_reason}",
            }

        checks: list[dict[str, Any]] = [{"name": "signature", "ok": True}]
        if expired:
            checks.append({"name": "expiry", "ok": False, "reason": "expired"})
            await enforce_min_response_time(_start, 0.05)
            return {"ok": False, "reason": "expired", "checks": checks}
        checks.append({"name": "expiry", "ok": True})

        # Layer 2: binding constraints.
        #
        # IntentMandate can be verified standalone. CartMandate may be
        # signature-only for inventory/display, but when an intent is
        # supplied it must satisfy it. PaymentMandate is different: a
        # payment is never settlement-authorizing without the full
        # Intent -> Cart -> Payment chain, so require both bindings.
        if kind == KIND_CART and payload.against_intent is not None:
            ok, reason = cart_satisfies_intent(body, payload.against_intent)
            checks.append({"name": "binds_intent", "ok": ok, "reason": reason})
            if not ok:
                await enforce_min_response_time(_start, 0.05)
                return {"ok": False, "reason": reason, "checks": checks}
        if kind == KIND_PAYMENT:
            if payload.against_cart is None or payload.against_intent is None:
                reason = (
                    "against_intent and against_cart are required when "
                    "verifying payment mandates"
                )
                checks.append(
                    {"name": "complete_triad", "ok": False, "reason": reason}
                )
                await enforce_min_response_time(_start, 0.05)
                return {"ok": False, "reason": reason, "checks": checks}
            ok, reason = complete_triad_chain(
                payload.against_intent, payload.against_cart, body
            )
            checks.append({"name": "complete_triad", "ok": ok, "reason": reason})
            if not ok:
                await enforce_min_response_time(_start, 0.05)
                return {"ok": False, "reason": reason, "checks": checks}

        await enforce_min_response_time(_start, 0.05)
        return {"ok": True, "reason": "", "checks": checks}

    assets_dir = STATIC_DIR / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    # v2 console read endpoints (Phase 1 of the local-hub plan,
    # 2026-06-10): register BEFORE the catch-all SPA fallback so
    # /api/v2/* gets matched as a real API route. See
    # nth_dao/web/v2_api.py for the contract.
    try:
        from . import v2_api as _v2_api

        _v2_api.register_v2_routes(app)
    except Exception as exc:  # noqa: BLE001
        # Don't take down the whole console because v2 routes failed
        # to register — the v1 dashboard still works.
        logger.warning("v2 api routes could not register: %s", exc)

    def _html_shell(content: str, status: int = 200) -> HTMLResponse:
        # 修复(2026-06-14)：HTML 外壳必须 **no-cache**。它引用 content-hash
        # 的 bundle(v2-<hash>.js);浏览器若缓存了 HTML,即使重新 build 出新
        # bundle,也会一直加载旧 HTML→旧 bundle引用→**旧版页面**(用户报告
        # "本地节点启动的 UI 往往是旧版")。hashed 的 /assets 仍可长缓存
        # (文件名随内容变,旧名不会被复用)。
        return HTMLResponse(
            content,
            status_code=status,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    def _request_is_direct_loopback_console(request: Request) -> bool:
        """Return true only for a direct browser request to a loopback host.

        A same-host reverse proxy also appears as a loopback TCP client. Never
        inject the operator token when the public Host is non-loopback or when
        proxy forwarding headers are present.
        """

        if not _request_client_is_loopback(request):
            return False
        if any(
            request.headers.get(name)
            for name in (
                "forwarded",
                "x-forwarded-for",
                "x-forwarded-host",
                "x-real-ip",
                "via",
                "cf-connecting-ip",
                "true-client-ip",
            )
        ):
            return False
        host = str(request.url.hostname or "").strip()
        if host.lower() == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _serve_console(file_name: str, request: Request):
        f = STATIC_DIR / file_name
        if f.exists():
            return _html_shell(
                _render_console_html(
                    f, app.state.nth_console_token,
                    embed_token=(
                        app.state.nth_embed_console_token
                        and _request_is_direct_loopback_console(request)
                    ),
                )
            )
        return _html_shell(_frontend_missing_html(), 503)

    # 默认入口 = v2 聊天优先控制台（2026-06-14）。此前 `/` 服务的是 v1
    # 旧版控制台，导致"本地启动 NTH DAO 打开的是旧版页面"——根因不只是
    # 缓存,而是默认 URL 本身指向 v1。现在 `/` 直接给 v2,v1 降级到 `/v1`
    # 保留(不删功能),与"降级不删除"一致。
    @app.get("/", response_class=HTMLResponse, response_model=None)
    @app.get("/v2", response_class=HTMLResponse, response_model=None)
    @app.get("/v2.html", response_class=HTMLResponse, response_model=None)
    def index(request: Request):
        return _serve_console("v2.html", request)

    @app.get("/v1", response_class=HTMLResponse, response_model=None)
    @app.get("/v1.html", response_class=HTMLResponse, response_model=None)
    def console_v1(request: Request):
        # 旧版（决策队列）控制台,保留备用。
        return _serve_console("index.html", request)

    @app.get("/{path:path}", include_in_schema=False, response_model=None)
    def frontend_fallback(path: str, request: Request):
        if path.startswith("api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        # 根目录静态资源(favicon / brand images 等):/assets 已挂载,但根级
        # 文件会落到这里。仅允许"无子路径 + 白名单后缀",防目录穿越,再交给
        # FileResponse(自动推断 content-type)。否则会被 SPA 回退成 HTML,
        # favicon 拿到的就是网页而非图标。
        if "/" not in path and path.endswith(
            (".svg", ".png", ".jpg", ".jpeg", ".ico", ".webmanifest", ".txt")
        ):
            candidate = STATIC_DIR / path
            if candidate.is_file():
                return FileResponse(candidate)
        # v1 深链接走旧版;其余(含 v2 深链接与未知路径)统一回 v2.html,
        # 让前端路由接管——默认就是新版。
        if path == "v1" or path == "v1.html" or path.startswith("v1/"):
            f = STATIC_DIR / "index.html"
            if f.exists():
                return _html_shell(
                    _render_console_html(
                        f, app.state.nth_console_token,
                        embed_token=(
                            app.state.nth_embed_console_token
                            and _request_is_direct_loopback_console(request)
                        ),
                    )
                )
        v2_file = STATIC_DIR / "v2.html"
        if v2_file.exists():
            return _html_shell(
                _render_console_html(
                    v2_file, app.state.nth_console_token,
                    embed_token=(
                        app.state.nth_embed_console_token
                        and _request_is_direct_loopback_console(request)
                    ),
                )
            )
        return JSONResponse(
            {"detail": "frontend assets are not built; run npm --prefix frontend run build"},
            status_code=503,
        )

    return app


def _build_udp_lan_responder(state: WebState) -> Optional[Any]:
    """Build the stdlib UDP responder for explicit LAN discovery mode."""
    if os.environ.get("NTH_LAN_PUBLISH", "1").strip() == "0":
        return None
    if os.environ.get("NTH_LAN_DISCOVERY", "").strip() != "1":
        return None
    if state.node_identity is None:
        return None
    try:
        config = state.membership.load_config()
        raw_agent_id = getattr(state.node_identity, "agent_id", "")
        node_network_id = (
            str(raw_agent_id) if raw_agent_id else DEFAULT_ADMIN_ID
        )
        custom_label = os.environ.get("NTH_LAN_LABEL", "").strip()
        if custom_label == "team_name":
            advertised_label = getattr(config, "team_name", "") or "NTH DAO"
        elif custom_label:
            advertised_label = custom_label[:60]
        else:
            advertised_label = "NTH DAO node"
        federation_base_url = _configured_public_base_url()
        metadata = {}
        if federation_base_url:
            metadata = {
                "http_url": federation_base_url,
                "federation_url": federation_base_url,
                "agent_card_url": (
                    f"{federation_base_url}/.well-known/agent.json"
                ),
            }
        return LANDiscovery(
            agent_id=node_network_id,
            label=advertised_label,
            capabilities=["nth-dao", "nth-dao-federation"],
            groups=["home"],
            ws_url=federation_base_url,
            pubkey_hex=getattr(state.node_identity, "pubkey_hex", "") or "",
            did=_safe_did(state.node_identity),
            metadata=metadata,
            psk=os.environ.get("NTH_DISCOVERY_PSK", "").strip(),
            port=configured_discovery_port(),
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("UDP LAN publish setup failed: %s", exc)
        return None


def _build_mdns_responder(state: WebState) -> Optional[Any]:
    """Build an mDNS responder without performing network I/O."""
    if os.environ.get("NTH_LAN_PUBLISH", "1").strip() == "0":
        return None
    if state.node_identity is None:
        return None

    try:
        from ..discovery.lan_mdns import MDNSDiscovery, is_available

        if not is_available():
            logger.info(
                "LAN DID publish skipped: install ``zeroconf`` "
                "(pip install zeroconf) to make this node discoverable "
                "on the local network",
            )
            return None
        config = state.membership.load_config()
        node_did = _safe_did(state.node_identity)
        node_pk = getattr(state.node_identity, "pubkey_hex", "") or ""
        raw_agent_id = getattr(state.node_identity, "agent_id", "")
        node_network_id = (
            str(raw_agent_id) if raw_agent_id else DEFAULT_ADMIN_ID
        )

        custom_label = os.environ.get("NTH_LAN_LABEL", "").strip()
        if custom_label == "team_name":
            advertised_label = getattr(config, "team_name", "") or "NTH DAO"
        elif custom_label:
            advertised_label = custom_label[:60]
        else:
            advertised_label = "NTH DAO node"

        federation_base_url = _configured_public_base_url()
        federation_metadata = {}
        if federation_base_url:
            federation_metadata = {
                "http_url": federation_base_url,
                "federation_url": federation_base_url,
                "agent_card_url": (
                    f"{federation_base_url}/.well-known/agent.json"
                ),
            }
        else:
            logger.info(
                "LAN DID publish has no HTTP federation URL; set "
                "NTH_PUBLIC_BASE_URL or bind with NTH_HOST + "
                "NTH_ALLOW_REMOTE_BIND=1 for cross-PC task discovery",
            )
        return MDNSDiscovery(
            agent_id=node_network_id,
            label=advertised_label,
            capabilities=["nth-dao", "nth-dao-federation"],
            groups=["home"],
            ws_url=federation_base_url,
            pubkey_hex=node_pk,
            did=node_did,
            metadata=federation_metadata,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "LAN DID publish setup failed; node will NOT be discoverable "
            "on the local network: %s",
            exc,
        )
        return None


def _bootstrap(state: WebState) -> None:
    # ── DID bootstrap (2026-06-07) ────────────────────────────────────────
    # Each fresh install must own a unique Ed25519 keypair persisted to
    # ``<workspace>/identity/identity.json`` (mode 0600). The DID derived
    # from that pubkey IS the workspace's permanent identifier on the
    # NTH DAO network - it's what other downloads search by, what
    # mandates are signed against, what the dashboard displays in the
    # top bar for the operator to share.
    #
    # The infrastructure in nth_dao.identity.load_or_generate already
    # does the heavy lifting; _bootstrap just has to call it before
    # building team.json so we can pin owner_pubkey on first boot.
    from ..identity import load_or_generate as _load_or_generate_identity

    try:
        node_identity = _load_or_generate_identity(
            state.workspace, label=DEFAULT_ADMIN_ID,
        )
    except Exception as exc:  # noqa: BLE001
        # Hard-fail visibility: if PyNaCl is missing or disk is read-only
        # we MUST surface that, not silently boot without an identity.
        # _bootstrap is called inside create_app(), so logger.warning is
        # the appropriate channel (uvicorn captures stderr).
        logger.warning(
            "could not auto-generate node identity on first boot: %s "
            "(install pynacl + ensure workspace is writable to enable "
            "the DID flow)", exc,
        )
        node_identity = None
    # Cache on the state so endpoints can read without re-parsing the
    # identity file on every request.
    state.node_identity = node_identity

    if node_identity is not None and getattr(node_identity, "can_sign", False):
        from ..trade_rules import TradeProposalInbox

        state.trade_proposal_inbox = TradeProposalInbox(
            state.workspace,
            receiver_did=node_identity.as_did(),
        )

    # Spine(Phase 2b):node_identity 就绪后建本 workspace 的签名因果日志(影子
    # 双写目标)。失败 / 日志损坏只降级为 None,**绝不阻断 hub 启动**(market
    # 回退到只写自身 feed;operator 可离线 verify_chain 排查)。
    if node_identity is not None and getattr(node_identity, "can_sign", False):
        try:
            from ..spine import SignedEventLog

            state.spine = SignedEventLog(
                state.workspace / "spine" / "events.jsonl", node_identity,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "spine init failed (%s); market dual-write disabled "
                "(feed-only). Run verify_chain to inspect the log.", exc,
            )
            state.spine = None
    if state.spine is not None and node_identity is not None:
        from ..trade_rules import (
            TradeExecutionCoordinator,
            TradeExecutionReceiptDispatchCoordinator,
            TradeDisputeStatementAuditCoordinator,
            TradeDisputeStatementDispatchCoordinator,
            TradeReceiptReviewCoordinator,
            TradeReceiptReviewDispatchCoordinator,
            TradeOrderAuditCoordinator,
            TradeOrderDispatchCoordinator,
            TradeOrderIntakeCoordinator,
        )

        state.trade_order_audit = TradeOrderAuditCoordinator(
            state.trade_order_audit_outbox,
            state.trade_order_store,
            state.spine,
        )
        state.trade_order_intake = TradeOrderIntakeCoordinator(
            state.trade_order_audit,
            receiver_identity=node_identity,
        )
        state.trade_order_dispatch = TradeOrderDispatchCoordinator(
            state.trade_order_dispatch_store,
            state.spine,
        )
        state.trade_execution_coordinator = TradeExecutionCoordinator(
            state.trade_execution_receipts,
            state.trade_execution_audit_outbox,
            state.spine,
        )
        state.trade_execution_dispatch = (
            TradeExecutionReceiptDispatchCoordinator(
                state.trade_execution_dispatch_store,
                state.spine,
            )
        )
        state.trade_receipt_review_coordinator = TradeReceiptReviewCoordinator(
            state.trade_receipt_reviews,
            state.spine,
        )
        state.trade_receipt_review_dispatch = (
            TradeReceiptReviewDispatchCoordinator(
                state.trade_receipt_review_dispatch_store,
                state.spine,
            )
        )
        state.trade_dispute_statement_audit = (
            TradeDisputeStatementAuditCoordinator(
                store=state.trade_dispute_statements,
                spine=state.spine,
            )
        )
        if state.trade_dispute_statement_dispatch_store is not None:
            state.trade_dispute_statement_dispatch = (
                TradeDisputeStatementDispatchCoordinator(
                    state.trade_dispute_statement_dispatch_store,
                    state.spine,
                )
            )
        try:
            dispute_recovery = _recover_trade_dispute_statement_audits(state)
            if dispute_recovery["anchored"] or dispute_recovery["failed"]:
                logger.info(
                    "trade Dispute Statement audit recovery: scanned=%d "
                    "anchored=%d verified=%d failed=%d",
                    dispute_recovery["scanned"],
                    dispute_recovery["anchored"],
                    dispute_recovery["verified_anchored"],
                    dispute_recovery["failed"],
                )
            if dispute_recovery["has_more"]:
                logger.warning(
                    "trade Dispute Statement audit recovery stopped at the "
                    "startup work budget; pending records remain"
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(
                "trade Dispute Statement audit recovery failed: %s",
                type(exc).__name__,
            )
        try:
            dispatch_recovery = (
                _recover_trade_dispute_statement_dispatch_acknowledgements(
                    state
                )
            )
            if dispatch_recovery["anchored"] or dispatch_recovery["failed"]:
                logger.info(
                    "trade Dispute Statement acknowledgement recovery: "
                    "scanned=%d anchored=%d failed=%d",
                    dispatch_recovery["scanned"],
                    dispatch_recovery["anchored"],
                    dispatch_recovery["failed"],
                )
            if dispatch_recovery["has_more"]:
                logger.warning(
                    "trade Dispute Statement acknowledgement recovery stopped "
                    "at the startup work budget"
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(
                "trade Dispute Statement acknowledgement recovery failed: %s",
                type(exc).__name__,
            )
        try:
            execution_recovery = _advance_trade_execution_recovery(state)
            if execution_recovery.anchored or execution_recovery.blocked:
                logger.info(
                    "trade execution audit recovery: scanned=%d anchored=%d "
                    "blocked=%d failed=%d",
                    execution_recovery.scanned,
                    execution_recovery.anchored,
                    execution_recovery.blocked,
                    execution_recovery.failed,
                )
            if execution_recovery.has_more:
                logger.warning(
                    "trade execution audit recovery stopped at the startup "
                    "work budget; background recovery will continue"
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("trade execution audit recovery failed: %s", exc)
        try:
            receipt_dispatch_cursor: str | None = None
            receipt_dispatch_scanned = 0
            receipt_dispatch_anchored = 0
            receipt_dispatch_completed = 0
            receipt_dispatch_failed = 0
            receipt_dispatch_has_more = False
            for _pass in range(_TRADE_ORDER_BOOT_RECOVERY_MAX_PASSES):
                receipt_dispatch = state.trade_execution_dispatch.reconcile(
                    limit=_TRADE_ORDER_BOOT_RECOVERY_BATCH,
                    after=receipt_dispatch_cursor,
                )
                receipt_dispatch_scanned += receipt_dispatch.scanned
                receipt_dispatch_anchored += receipt_dispatch.anchored
                receipt_dispatch_completed += receipt_dispatch.completed
                receipt_dispatch_failed += receipt_dispatch.failed
                receipt_dispatch_has_more = receipt_dispatch.has_more
                receipt_dispatch_cursor = receipt_dispatch.next_cursor or None
                if not receipt_dispatch_has_more:
                    break
            if receipt_dispatch_anchored or receipt_dispatch_completed:
                logger.info(
                    "trade Execution Receipt acknowledgement recovery: "
                    "scanned=%d anchored=%d completed=%d failed=%d",
                    receipt_dispatch_scanned,
                    receipt_dispatch_anchored,
                    receipt_dispatch_completed,
                    receipt_dispatch_failed,
                )
            if receipt_dispatch_failed or receipt_dispatch_has_more:
                logger.warning(
                    "trade Execution Receipt acknowledgement recovery "
                    "retained unfinished records for operator retry"
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(
                "trade Execution Receipt acknowledgement recovery failed: %s",
                exc,
            )
        try:
            review_cursor: str | None = None
            review_scanned = 0
            review_anchored = 0
            review_conflicted = 0
            review_failed = 0
            review_has_more = False
            for _pass in range(_TRADE_ORDER_BOOT_RECOVERY_MAX_PASSES):
                review_recovery = (
                    state.trade_receipt_review_coordinator.reconcile(
                        limit=_TRADE_ORDER_BOOT_RECOVERY_BATCH,
                        after_digest=review_cursor,
                    )
                )
                review_scanned += review_recovery.scanned
                review_anchored += review_recovery.anchored
                review_conflicted += review_recovery.conflicted
                review_failed += review_recovery.failed
                review_has_more = review_recovery.has_more
                review_cursor = review_recovery.next_cursor
                if not review_has_more:
                    break
            if review_anchored or review_conflicted:
                logger.info(
                    "trade Receipt Review recovery: scanned=%d anchored=%d "
                    "conflicted=%d failed=%d",
                    review_scanned,
                    review_anchored,
                    review_conflicted,
                    review_failed,
                )
            if review_failed or review_has_more:
                logger.warning(
                    "trade Receipt Review recovery retained unfinished "
                    "records for operator retry"
                )
            review_dispatch_cursor: str | None = None
            review_dispatch_scanned = 0
            review_dispatch_anchored = 0
            review_dispatch_completed = 0
            review_dispatch_failed = 0
            review_dispatch_has_more = False
            for _pass in range(_TRADE_ORDER_BOOT_RECOVERY_MAX_PASSES):
                review_dispatch = (
                    state.trade_receipt_review_dispatch.reconcile(
                        limit=_TRADE_ORDER_BOOT_RECOVERY_BATCH,
                        after=review_dispatch_cursor,
                    )
                )
                review_dispatch_scanned += review_dispatch.scanned
                review_dispatch_anchored += review_dispatch.anchored
                review_dispatch_completed += review_dispatch.completed
                review_dispatch_failed += review_dispatch.failed
                review_dispatch_has_more = review_dispatch.has_more
                review_dispatch_cursor = (
                    review_dispatch.next_cursor or None
                )
                if not review_dispatch_has_more:
                    break
            if review_dispatch_anchored or review_dispatch_completed:
                logger.info(
                    "trade Receipt Review acknowledgement recovery: "
                    "scanned=%d anchored=%d completed=%d failed=%d",
                    review_dispatch_scanned,
                    review_dispatch_anchored,
                    review_dispatch_completed,
                    review_dispatch_failed,
                )
            if review_dispatch_failed or review_dispatch_has_more:
                logger.warning(
                    "trade Receipt Review acknowledgement recovery retained "
                    "unfinished records for operator retry"
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("trade Receipt Review recovery failed: %s", exc)
        try:
            order_scanned = 0
            order_anchored = 0
            order_verified = 0
            order_blocked = 0
            order_failed = 0
            order_recovery_pending = False
            for _pass in range(_TRADE_ORDER_BOOT_RECOVERY_MAX_PASSES):
                order_recovery = state.trade_order_audit.reconcile(
                    limit=_TRADE_ORDER_BOOT_RECOVERY_BATCH
                )
                order_scanned += order_recovery.scanned
                order_anchored += order_recovery.anchored
                order_verified += order_recovery.verified_anchored
                order_blocked += order_recovery.blocked
                order_failed += order_recovery.failed
                order_recovery_pending = bool(
                    state.trade_order_audit_outbox.pending(limit=1)
                )
                if not order_recovery_pending:
                    break
                if order_recovery.anchored == 0 and order_recovery.blocked == 0:
                    # The remaining first page failed. Retain it for an
                    # operator retry instead of spinning during boot.
                    break
            if order_recovery_pending:
                logger.warning(
                    "trade Order audit recovery stopped at the startup "
                    "work budget; pending records remain for operator reconcile"
                )
            if order_anchored or order_blocked or order_failed:
                logger.info(
                    "trade Order audit recovery: scanned=%d anchored=%d "
                    "verified=%d blocked=%d failed=%d",
                    order_scanned,
                    order_anchored,
                    order_verified,
                    order_blocked,
                    order_failed,
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("trade Order audit recovery failed: %s", exc)
        try:
            dispatch_cursor: str | None = None
            dispatch_scanned = 0
            dispatch_anchored = 0
            dispatch_completed = 0
            dispatch_failed = 0
            dispatch_has_more = False
            for _pass in range(_TRADE_ORDER_BOOT_RECOVERY_MAX_PASSES):
                dispatch_recovery = state.trade_order_dispatch.reconcile(
                    limit=_TRADE_ORDER_BOOT_RECOVERY_BATCH,
                    after=dispatch_cursor,
                )
                dispatch_scanned += dispatch_recovery.scanned
                dispatch_anchored += dispatch_recovery.anchored
                dispatch_completed += dispatch_recovery.completed
                dispatch_failed += dispatch_recovery.failed
                dispatch_has_more = dispatch_recovery.has_more
                dispatch_cursor = dispatch_recovery.next_cursor or None
                if not dispatch_has_more:
                    break
            if dispatch_anchored or dispatch_completed:
                logger.info(
                    "trade Order acknowledgement recovery: scanned=%d "
                    "anchored=%d completed=%d failed=%d",
                    dispatch_scanned,
                    dispatch_anchored,
                    dispatch_completed,
                    dispatch_failed,
                )
            if dispatch_failed:
                logger.warning(
                    "trade Order acknowledgement recovery retained %d "
                    "record(s) for operator retry",
                    dispatch_failed,
                )
            if dispatch_has_more:
                logger.warning(
                    "trade Order acknowledgement recovery stopped at the "
                    "startup work budget; more records remain"
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(
                "trade Order acknowledgement recovery failed: %s", exc
            )
    if state.spine is not None and state.trade_proposal_inbox is not None:
        from ..trade_rules import (
            RuleRecognitionAuditCoordinator,
            RuleRecognitionPolicyAuditCoordinator,
            RuleRecognitionPolicyStore,
            TradeProposalAuditCoordinator,
        )

        try:
            proposal_usage = state.trade_proposal_inbox.reconcile_usage()
            logger.info(
                "trade Proposal inbox usage: records=%d bytes=%d",
                proposal_usage["records"],
                proposal_usage["bytes"],
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("trade Proposal inbox usage rebuild failed: %s", exc)
        state.trade_proposal_audit = TradeProposalAuditCoordinator(
            state.trade_proposal_inbox,
            state.spine,
            node_identity,
        )
        try:
            proposal_cursor = None
            proposal_scanned = 0
            proposal_anchored = 0
            proposal_failed = 0
            while True:
                proposal_recovery = state.trade_proposal_audit.reconcile(
                    limit=1_000,
                    after=proposal_cursor,
                )
                proposal_scanned += proposal_recovery.scanned
                proposal_anchored += proposal_recovery.anchored
                proposal_failed += proposal_recovery.failed
                proposal_cursor = proposal_recovery.next_cursor
                if not proposal_recovery.has_more:
                    break
            if proposal_anchored or proposal_failed:
                logger.info(
                    "trade Proposal audit recovery: scanned=%d anchored=%d failed=%d",
                    proposal_scanned,
                    proposal_anchored,
                    proposal_failed,
                )
            proposal_archive_scanned = 0
            proposal_archived = 0
            proposal_archive_failures = 0
            while True:
                proposal_archive = state.trade_proposal_audit.archive_expired(
                    at=datetime.now(timezone.utc),
                    limit=1_000,
                )
                proposal_archive_scanned += proposal_archive.scanned
                proposal_archived += proposal_archive.archived
                proposal_archive_failures += len(
                    proposal_archive.failure_digests
                )
                if proposal_archive.scanned < 1_000:
                    break
                if proposal_archive.archived == 0:
                    # Every item in this page failed. Avoid an infinite boot
                    # loop while retaining the records for operator recovery.
                    break
            if proposal_archived or proposal_archive_failures:
                logger.info(
                    "trade Proposal expiry archive: scanned=%d archived=%d failed=%d",
                    proposal_archive_scanned,
                    proposal_archived,
                    proposal_archive_failures,
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("trade Proposal audit recovery failed: %s", exc)

        state.trade_rule_recognition_audit = (
            RuleRecognitionAuditCoordinator(
                store=state.trade_rule_recognitions,
                spine=state.spine,
            )
        )
        node_did = _safe_did(node_identity)
        if node_did:
            state.trade_rule_recognition_policy_store = (
                RuleRecognitionPolicyStore.open_or_create_for_identity(
                    state.workspace,
                    identity_did=node_did,
                )
            )
            state.trade_rule_recognition_policy_audit = (
                RuleRecognitionPolicyAuditCoordinator(
                    policy_store=(
                        state.trade_rule_recognition_policy_store
                    ),
                    package_store=state.trade_rule_packages,
                    recognition_audit=state.trade_rule_recognition_audit,
                    spine=state.spine,
                )
            )

    config = state.membership.load_config()
    if not config.admin_ids and not config.member_ids:
        config = state.membership.init_team(
            "NTH DAO",
            policy="open",
            admin_ids=[DEFAULT_ADMIN_ID],
        )
    elif DEFAULT_ADMIN_ID not in config.admin_ids:
        if DEFAULT_ADMIN_ID not in config.member_ids:
            config.member_ids.append(DEFAULT_ADMIN_ID)
        config.admin_ids.append(DEFAULT_ADMIN_ID)
        config.roles[DEFAULT_ADMIN_ID] = TeamRole.OWNER.value
        state.membership.save_config(config)

    # Pin the generated DID into team.json so any peer fetching this
    # workspace's config can verify our identity claim.
    #
    # R-30 (2026-06-08): three cases for the second-and-later boots:
    #   (a) team.json has no owner_pubkey   -> first ever pin (write)
    #   (b) team.json owner_pubkey matches  -> just rebind in memory,
    #                                          do NOT re-write (we'd
    #                                          burn the mtime cache
    #                                          and uselessly change
    #                                          team.json on every boot)
    #   (c) team.json owner_pubkey differs  -> drift; log loudly and

    #                                          refuse to silently
    #                                          override (could indicate
    #                                          identity.json swap /
    #                                          backup restore)
    if (
        node_identity is not None
        and getattr(node_identity, "can_sign", False)
    ):
        node_pubkey_hex = (
            getattr(node_identity, "pubkey_hex", "") or ""
        )
        if not config.owner_pubkey:
            # Case (a): first-time pin
            try:
                state.membership.enable_signed_owner(
                    node_identity, actor_id=DEFAULT_ADMIN_ID,
                )
                logger.info(
                    "pinned node identity to team.json: pubkey_prefix=%s",
                    node_pubkey_hex[:16],
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "could not pin owner identity to team.json: %s "
                    "(team.json stays unsigned; DID is still "
                    "available via /api/identity)", exc,
                )
        elif config.owner_pubkey.lower() == node_pubkey_hex.lower():
            # Case (b): same identity, second boot. Rebind the signing
            # key on the MembershipManager so subsequent save_config()
            # calls produce valid signatures - WITHOUT re-writing
            # team.json (would burn the R-4 cache + mtime).
            state.membership._owner_identity = node_identity
            logger.debug(
                "rebound existing owner identity on MembershipManager "
                "(team.json already signed by this key)"
            )
        else:
            # Case (c): drift. team.json was signed by a DIFFERENT
            # key than the one identity.json currently holds. This
            # usually means the operator restored a backup or rotated
            # identity.json without resigning team.json. Refuse to
            # silently overwrite - the operator must make an explicit
            # decision.
            logger.error(
                "identity drift: team.json pins owner_pubkey=%s but "
                "identity.json holds %s. team.json will not be "
                "re-signed automatically. Either restore the original "
                "identity.json or run a deliberate key-rotation flow.",
                config.owner_pubkey[:16], node_pubkey_hex[:16],
            )

    if not state.groups.get_channel(DEFAULT_CHANNEL_ID):
        state.groups.create_channel(
            "general",
            created_by=config.admin_ids[0] if config.admin_ids else DEFAULT_ADMIN_ID,
            channel_id=DEFAULT_CHANNEL_ID,
            topic="Default DAO channel",
        )
    try:
        from .legacy_demo_cleanup import purge_legacy_demo_state

        purge_legacy_demo_state(state)
    except (OSError, RuntimeError, ValueError) as exc:
        logger.warning("legacy demo cleanup did not complete: %s", exc)


def _require_member_or_joinable(state: WebState, agent_id: str) -> None:
    config = state.membership.load_config()
    if config.role_for(agent_id) != TeamRole.GUEST:
        return
    ok, reason = state.membership.ensure_member(agent_id)
    if not ok:
        raise HTTPException(status_code=403, detail=reason)


def _require_explicit_actor_id(actor_id: str) -> None:
    if not isinstance(actor_id, str) or not actor_id.strip():
        raise HTTPException(
            status_code=400,
            detail="actor_id is required for mandate routes",
        )


def _workspace_is_locally_accessible(workspace: Path) -> bool:
    """C-2 (2026-06-07): honest check that the workspace path is on
    the local filesystem and readable by this process.

    Returns False (so the dashboard can warn the user) when:
      * the path does not exist
      * the path exists but is not a directory
      * the path exists but listing it raises a PermissionError or OSError
        (e.g. unmounted network share, broken symlink)

    Returns True in the normal in-process case where the workspace is
    a regular local directory we can read.
    """
    try:
        if not workspace.exists() or not workspace.is_dir():
            return False
        # Probe one directory listing - cheap on Windows/posix and
        # surfaces broken-symlink / no-access cases that ``exists()``
        # alone misses.
        next(iter(workspace.iterdir()), None)
        return True
    except (PermissionError, OSError):
        return False


def _require_member(state: WebState, agent_id: str) -> None:
    config = state.membership.load_config()
    if config.role_for(agent_id) == TeamRole.GUEST:
        raise HTTPException(status_code=403, detail=f"agent '{agent_id}' is not a member")


def _require_admin(state: WebState, agent_id: str) -> None:
    _require_permission(state, agent_id, "manage_members")


def _require_permission(state: WebState, agent_id: str, permission: str) -> None:
    if not state.membership.has_permission(agent_id, permission):
        raise HTTPException(status_code=403, detail=f"agent '{agent_id}' lacks permission '{permission}'")


def _team_dict(config: TeamConfig) -> dict[str, Any]:
    data = config.to_dict()
    data["roles"] = dict(sorted(data.get("roles", {}).items()))
    return data


def _members(state: WebState, config: TeamConfig) -> list[dict[str, Any]]:
    online = {r.agent_id for r in state.registry.list_alive()}
    rows: list[dict[str, Any]] = []
    for agent_id in sorted(config.member_ids):
        code, pubkey_hex, contact = _resolve_member_identity(state, agent_id)
        row = {
            "agent_id": agent_id,
            "role": config.role_for(agent_id).value,
            "online": agent_id in online,
            "code": code,
            "did": "",
            "pubkey_prefix": pubkey_hex[:16] if pubkey_hex else "",
        }
        if agent_id == DEFAULT_ADMIN_ID and state.node_identity is not None:
            row["did"] = _safe_did(state.node_identity)
        elif contact is not None and contact.did:
            row["did"] = contact.did
        rows.append(row)
    return rows


def _actor_dict(
    agent_id: str,
    role: str,
    state: Optional[WebState] = None,
) -> dict[str, Any]:
    """Standard shape for the 'who am I' block on every state response.

    DID bootstrap (2026-06-07): when ``state`` is supplied AND
    ``agent_id`` matches the bootstrap admin, the node's persistent
    did:key is included so the dashboard can show "your DID is X" in
    the top bar. Other agents render with did="" (they are remote
    peers whose DID lives in their own workspace, not ours).
    """
    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "role": role,
        "code": code_for_agent_id(agent_id),
        "did": "",
        "pubkey_hex": "",
    }
    if state is not None:
        code, pubkey_hex, contact = _resolve_member_identity(state, agent_id)
        payload["code"] = code
        if pubkey_hex:
            payload["pubkey_hex"] = pubkey_hex
        if agent_id == DEFAULT_ADMIN_ID and state.node_identity is not None:
            payload["did"] = _safe_did(state.node_identity)
        elif contact is not None and contact.did:
            payload["did"] = contact.did
    return payload


def _resolve_member_identity(
    state: "WebState", agent_id: str,
) -> "tuple[str, str, Optional[ContactRecord]]":
    """Single source of truth for ``(code, pubkey_hex, contact)``.

    R-46..R-51 (2026-06-08): the previous split into ``_code_for_admin``
    and ``_code_for_member`` led to three problems:

      * /api/identity inlined its own code derivation (R-47)
      * by_code handler re-fetched the ContactBook contact (R-48, R-51)
      * the admin fallback path silently returned the LITERAL-admin
        hash ``"8c69-76e5"`` when node_identity carried no pubkey
        (R-46) - reintroducing the global cross-install collision the
        R-35 fix was supposed to eliminate

    This single helper returns everything any caller needs in one
    look-up:

      code:
        The visible 8-hex handle. **Empty string** when this is the
        bootstrap admin AND we have no crypto material - downstream
        UI must treat "" as "code unavailable" and either hide the
        widget or show a clear "install pynacl" hint. The bootstrap
        admin's code MUST NOT fall back to the agent_id-hash because
        that hash is the cross-install constant we set out to kill.
      pubkey_hex:
        64-hex Ed25519 pubkey if known. Either lifted from
        node_identity (admin), from the ContactBook record
        (pubkey_hex directly stored, or decoded from contact.did via
        did:key), or empty when the contact is agent_id-only.
      contact:
        The ContactBook record we resolved, or None. Returning it
        lets the caller pick up label/source/added_at without a
        second cache hit (R-51).
    """
    # Path 1: bootstrap admin
    if agent_id == DEFAULT_ADMIN_ID:
        if state.node_identity is not None:
            pk = getattr(state.node_identity, "pubkey_hex", "") or ""
            if pk:
                return code_for_pubkey(pk), pk, None
        # R-46: bootstrap admin with no crypto. Empty code is the
        # honest signal. The agent_id-hash fallback would collide
        # globally across every PyNaCl-missing install.
        return "", "", None

    # Path 2: ContactBook resolution for other members
    try:
        contact = state.contacts.get(agent_id)
    except Exception:  # noqa: BLE001
        contact = None
    pk = ""
    if contact is not None:
        pk = contact.pubkey_hex or ""
        # R-50: if the contact only carries did, derive pubkey from
        # it. did:key encodes the pubkey deterministically so this
        # is fully equivalent to the contact.pubkey_hex case for
        # downstream code derivation.
        if not pk and contact.did:
            # R-58: did_key helpers are imported at module scope.
            try:
                if is_did_key(contact.did):
                    pk = decode_ed25519_did_key_hex(contact.did) or ""
            except Exception:  # noqa: BLE001
                pk = ""
        # R-61 (2026-06-08): when BOTH pubkey_hex and did are stored
        # and they disagree, the file has been written inconsistently
        # by an external tool. We honour pubkey_hex (it's the literal
        # crypto identifier; did is its encoded form) but log so the
        # operator notices.
        elif pk and contact.did:
            try:
                if is_did_key(contact.did):
                    claimed = decode_ed25519_did_key_hex(contact.did) or ""
                    if claimed and claimed.lower() != pk.lower():
                        logger.warning(
                            "contact %s has did/pubkey mismatch: "
                            "did claims pubkey %s but pubkey_hex is "
                            "%s. Trusting pubkey_hex.",
                            agent_id, claimed[:16], pk[:16],
                        )
            except Exception:  # noqa: BLE001
                pass
    if pk:
        return code_for_pubkey(pk), pk, contact

    # Path 3: legacy agent_id-derived. Per-contact stable (because
    # agent_ids like "alice"/"bob" are themselves distinct per row)
    # so the cross-install collision only happens when two installs
    # add the same agent_id LITERAL - acceptable trade-off, since
    # the safer pubkey path is preferred whenever pubkey is known.
    #
    # R-62 (2026-06-08) — attack-surface note: this path returns a
    # code derived purely from a caller-supplied agent_id string. An
    # attacker who can register or impersonate an agent_id can choose
    # one whose hash collides with a high-value pubkey-derived code
    # (8-hex namespace is small; ~16M space). Mitigations elsewhere:
    #   * `by_code` lookups prefer pubkey-derived rows (search
    #     iterates registry + contacts; pubkey matches outrank
    #     agent_id matches because the registry row carries pubkey)
    #   * the UI surfaces DID alongside code when the consumer needs
    #     to authenticate, not just label
    # If you tighten this further, do NOT silently return "" here —
    # legacy agent-only contacts are real and must remain addressable.
    return code_for_agent_id(agent_id), "", contact


def _code_for_admin(state: "WebState") -> str:
    """Convenience accessor — code-only view of the bootstrap admin's
    identity.

    Use this when you genuinely only need the visible code (e.g. a
    response body field that doesn't also expose pubkey). If you also
    need the pubkey or the contact record, call
    ``_resolve_member_identity(state, DEFAULT_ADMIN_ID)`` directly to
    avoid a second resolution round-trip.

    R-63 (2026-06-08): renamed from "Compatibility shim" — this is a
    permanent first-class helper, not a deprecated transition step.
    """
    code, _, _ = _resolve_member_identity(state, DEFAULT_ADMIN_ID)
    return code


def _code_for_member(state: "WebState", agent_id: str) -> str:
    """Convenience accessor — code-only view of an arbitrary member's
    identity.

    Same trade-off as :func:`_code_for_admin`: prefer
    ``_resolve_member_identity(state, agent_id)`` when you also need
    the pubkey or contact record so the ContactBook lookup happens
    exactly once.

    R-63 (2026-06-08): renamed from "Compatibility shim".
    """
    code, _, _ = _resolve_member_identity(state, agent_id)
    return code


def _safe_did(identity: Any) -> str:
    """DID bootstrap helper: ``AgentIdentity.as_did()`` is a method,
    not a property, and only crypto-capable identities expose one.
    Centralises the "did:key:... or '' " contract so every endpoint
    serialises identities the same way."""
    if identity is None:
        return ""
    as_did = getattr(identity, "as_did", None)
    if not callable(as_did):
        return ""
    try:
        value = as_did()
    except Exception:  # noqa: BLE001
        return ""
    return value or ""


def _score_contact_query(query: str, values: list[str]) -> tuple[float, list[str]]:
    """Simple deterministic scorer for member/contact search."""
    q = query.strip().lower()
    if not q:
        return 0.0, []
    q_compact = q.replace("-", "")
    score = 0.0
    matched: list[str] = []
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        v = value.lower()
        candidates = {v, v.replace("-", "")}
        if q in candidates or q_compact in candidates:
            score += 3.0
            matched.append(value)
        elif any(candidate.startswith(q) or candidate.startswith(q_compact) for candidate in candidates):
            score += 1.5
            matched.append(value)
        elif any(q in candidate or q_compact in candidate for candidate in candidates):
            score += 0.8
            matched.append(value)
    return score, matched


# ─── v0.9.7: multi-DAO helpers ────────────────────────────────────────────
#
# An agent participates in one or more DAOs:
#   - "home" — the local workspace team (single global membership). slug="home".
#   - "group" — any GroupRecord from the cross-workspace GroupRegistry where
#     the agent's pubkey is in admin_pubkeys or member_pubkeys.
#
# DAO-scoped channels carry a `dao-<slug>-` prefix on channel_id. The home
# DAO owns everything WITHOUT that prefix (so existing single-DAO installs
# keep working unchanged).

HOME_DAO_SLUG = "home"


def _dao_channel_prefix(slug: str) -> str:
    """`""` for the home DAO; `dao-<slug>-` for registered groups."""
    if not slug or slug == HOME_DAO_SLUG:
        return ""
    return f"dao-{slug}-"


def _dao_owns_channel(slug: str, channel_id: str) -> bool:
    """True if the given channel_id belongs to the slug-scoped DAO.

    Home DAO owns everything that does NOT start with `dao-`. Group DAOs own
    only ids starting with their own `dao-<slug>-` prefix.
    """
    if not slug or slug == HOME_DAO_SLUG:
        return not channel_id.startswith("dao-")
    return channel_id.startswith(_dao_channel_prefix(slug))


def _list_my_daos(state: WebState, actor_pubkey_hex: str, actor_id: str) -> list[dict[str, Any]]:
    """Return [home, *joined_groups, *browsable_groups] for the sidebar.

    When `actor_pubkey_hex` is empty (e.g. wallet still loading), we list
    every group as "joinable" so the sidebar isn't empty — but `joined`
    flags reflect actual membership.
    """
    config = state.membership.load_config()
    daos: list[dict[str, Any]] = []
    home_member_count = len(config.member_ids)
    daos.append({
        "slug": HOME_DAO_SLUG,
        "display_name": config.team_name or "Home Workspace",
        "kind": "home",
        "group_id": "",
        "description": "Local workspace — the team you're directly part of.",
        "policy": config.join_policy,
        "joined": config.role_for(actor_id).value != "guest",
        "member_count": home_member_count,
    })
    actor_pk = (actor_pubkey_hex or "").lower()
    for record in state.group_registry.list_all():
        all_pubkeys = {p.lower() for p in (record.admin_pubkeys + record.member_pubkeys)}
        joined = bool(actor_pk and actor_pk in all_pubkeys)
        daos.append({
            "slug": record.slug,
            "display_name": record.display_name,
            "kind": "group",
            "group_id": record.group_id,
            "description": record.description,
            "policy": record.policy.value if hasattr(record.policy, "value") else str(record.policy),
            "joined": joined,
            "member_count": len(record.member_pubkeys),
            "admin_count": len(record.admin_pubkeys),
        })
    return daos


def _resolve_dao(state: WebState, slug: str) -> tuple[str, Optional[Any]]:
    """Return ("home", None) or ("group", GroupRecord), or 404."""
    if not slug or slug == HOME_DAO_SLUG:
        return ("home", None)
    record = state.group_registry.load_by_slug(slug)
    if record is None:
        # Tolerate group_id lookups too — handy when the slug is unknown to
        # the caller but the group_id was carried over from a search result.
        record = state.group_registry.load_by_id(slug)
    if record is None:
        raise HTTPException(status_code=404, detail=f"DAO '{slug}' not found")
    return ("group", record)


def _members_from_group(record: Any) -> list[dict[str, Any]]:
    """Synthesize a `members` array from a GroupRecord's pubkey set.

    Every member carries a copy-and-paste-able ``code`` derived from
    their pubkey so the UI can show a stable handle instead of the
    raw 64-char hex. We can't tell online/offline from the registry
    alone, so ``online`` is False everywhere — LAN discovery fills
    that in later.
    """
    admin_set = {p.lower() for p in record.admin_pubkeys}
    out: list[dict[str, Any]] = []
    for pk in sorted(set(record.member_pubkeys + record.admin_pubkeys)):
        out.append({
            "agent_id": pk[:16],   # short display id
            "role": "admin" if pk.lower() in admin_set else "member",
            "online": False,
            "pubkey_hex": pk,
            "code": code_for_pubkey(pk),
        })
    return out


def _dao_meta_dict(slug: str, kind: str, record: Any, *, member_count: int) -> dict[str, Any]:
    if kind == "home":
        return {
            "slug": HOME_DAO_SLUG,
            "kind": "home",
            "display_name": "Home Workspace",
            "group_id": "",
            "description": "Local workspace — the team you're directly part of.",
            "policy": "",
            "member_count": member_count,
        }
    return {
        "slug": record.slug,
        "kind": "group",
        "display_name": record.display_name,
        "group_id": record.group_id,
        "description": record.description,
        "policy": record.policy.value if hasattr(record.policy, "value") else str(record.policy),
        "member_count": member_count,
        "admin_count": len(record.admin_pubkeys),
        "founder_pubkey": record.founder_pubkey if hasattr(record, "founder_pubkey") else "",
    }


# v0.10 T-9: cheap shape check for the Mandate routes. We compare
# against the W3C VC ``type`` array set by ``build_*_mandate`` rather
# than parsing the body, so a draft body the wallet has not yet
# signed still passes (the sidebar saves drafts) while obvious junk
# is rejected before it produces a useless digest file on disk.

_EXPECTED_TYPE_TOKEN = {
    KIND_INTENT: "IntentMandate",
    KIND_CART: "CartMandate",
    KIND_PAYMENT: "PaymentMandate",
}


def _looks_like_mandate(kind: str, body: dict[str, Any]) -> bool:
    """True if ``body`` is W3C VC shaped and tagged for the kind.

    The check is intentionally minimal - it must accept any well
    formed mandate the build_*_mandate functions produce, including
    pre-signing drafts (no proof block yet). It must reject:

      * non-dicts and dicts missing the W3C VC backbone,
      * mandates of one kind being saved under another kind's slot.

    Anything stricter belongs in ``verify_*_mandate``.
    """
    if not isinstance(body, dict):
        return False
    if "@context" not in body or "credentialSubject" not in body:
        return False
    expected = _EXPECTED_TYPE_TOKEN.get(kind)
    if expected is None:
        return False
    type_field = body.get("type")
    if isinstance(type_field, str):
        return type_field == expected
    if isinstance(type_field, list):
        return expected in type_field
    return False


# v0.10 T-9: sidebar row summarisers - extract only the fields the
# UI displays, so the JSON over the wire stays small even when carts
# carry rich line-item arrays. Each summariser tolerates missing
# fields (the store may hold a draft mandate the UI saved before
# signing) and falls back to empty strings rather than raising.


def _summarise_intent(mandate: dict[str, Any]) -> dict[str, Any]:
    """Project an IntentMandate to its sidebar row.

    Field map per ``nth_dao.mandate.intent.build_intent_mandate``:

      - top-level ``issuer`` is the DAO did:key
      - top-level ``validUntil`` is the expiry timestamp
      - ``credentialSubject.id`` is the agent_did being authorised
      - ``credentialSubject.purpose`` is the human label
      - constraints sit under ``credentialSubject.constraints.*``
    """
    subject = mandate.get("credentialSubject") or {}
    constraints = subject.get("constraints") or {}
    max_amount = constraints.get("max_amount") or {}
    try:
        digest = intent_mandate_digest(mandate)
    except (KeyError, TypeError, ValueError):  # pragma: no cover - malformed body in store
        digest = ""
    return {
        "kind": KIND_INTENT,
        "digest": digest,
        "issuer": mandate.get("issuer", ""),
        "agent": subject.get("id", ""),
        "purpose": subject.get("purpose", ""),
        "max_amount": {
            "currency": max_amount.get("currency", ""),
            "value": str(max_amount.get("value", "")),
        },
        "expires_at": mandate.get("validUntil", ""),
        "expired": _safe_is_expired(is_intent_expired, mandate),
        "allowed_counterparties": list(
            constraints.get("allowed_counterparties") or []
        ),
        "allowed_settlement_methods": list(
            constraints.get("allowed_settlement_methods") or []
        ),
    }


def _summarise_cart(mandate: dict[str, Any]) -> dict[str, Any]:
    """Project a CartMandate to its sidebar row.

    Field map per ``nth_dao.mandate.cart.build_cart_mandate``:

      - top-level ``issuer`` is the seller did:key
      - top-level ``validUntil`` is the offer-window expiry
      - ``credentialSubject.id`` is the BUYER did (not surfaced -
        the sidebar groups by issuer instead)
      - ``credentialSubject.intent_mandate_digest`` is the binding
      - line items live under ``credentialSubject.items``
    """
    subject = mandate.get("credentialSubject") or {}
    total = subject.get("total") or {}
    try:
        digest = cart_mandate_digest(mandate)
    except (KeyError, TypeError, ValueError):  # pragma: no cover - malformed body in store
        digest = ""
    return {
        "kind": KIND_CART,
        "digest": digest,
        "issuer": mandate.get("issuer", ""),
        "intent_digest": subject.get("intent_mandate_digest", ""),
        "total": {
            "currency": total.get("currency", ""),
            "value": str(total.get("value", "")),
        },
        "settlement_methods": list(subject.get("settlement_methods") or []),
        "expires_at": mandate.get("validUntil", ""),
        "expired": _safe_is_expired(is_cart_expired, mandate),
        "line_item_count": len(subject.get("items") or []),
    }


def _summarise_payment(mandate: dict[str, Any]) -> dict[str, Any]:
    """Project a PaymentMandate to its sidebar row.

    Field map per ``nth_dao.mandate.payment.build_payment_mandate``:

      - top-level ``issuer`` is the DAO authorising settlement
      - top-level ``validUntil`` is the settlement-authority window
      - ``credentialSubject.id`` is the PAYEE did:key
      - ``credentialSubject.cart_mandate_digest`` is the binding
      - ``credentialSubject.settlement_choice`` is the chosen rail
    """
    subject = mandate.get("credentialSubject") or {}
    try:
        digest = payment_mandate_digest(mandate)
    except (KeyError, TypeError, ValueError):  # pragma: no cover - malformed body in store
        digest = ""
    return {
        "kind": KIND_PAYMENT,
        "digest": digest,
        "issuer": mandate.get("issuer", ""),
        "cart_digest": subject.get("cart_mandate_digest", ""),
        "payee": subject.get("id", ""),
        "settlement_choice": subject.get("settlement_choice", ""),
        "issued_at": mandate.get("issuanceDate", ""),
        "expires_at": mandate.get("validUntil", ""),
        "expired": _safe_is_expired(is_payment_expired, mandate),
    }


def _safe_is_expired(checker, mandate: dict[str, Any]) -> bool:
    """Best-effort expiry check; malformed timestamps -> False.

    The store may hold drafts during sidebar editing; surface them as
    not-expired rather than 500-ing the whole listing route.
    """
    try:
        return bool(checker(mandate))
    except (KeyError, TypeError, ValueError):
        return False


def _frontend_missing_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nᵗʰ DAO</title>
</head>
<body>
  <main>
    <h1>N<sup style="font-size:0.58em;vertical-align:super;line-height:0">th</sup> DAO</h1>
    <p>Frontend assets are not built. Run <code>npm --prefix frontend run build</code>.</p>
  </main>
</body>
</html>"""


def _embed_console_token_in_page() -> bool:
    """是否把 console token 直接注入页面(默认 True,本地便利)。

    公网部署应设 ``NTH_CONSOLE_TOKEN_IN_PAGE=0``:页面不再内嵌全权 token,改由
    测试者带外索取后存浏览器 ``localStorage``(见 ``_render_console_html`` 的引导
    脚本)—— 杜绝"任何拿到 URL 的人 GET / 即得全权 token"。读面仍匿名可浏览。
    """
    raw = os.environ.get(CONSOLE_TOKEN_IN_PAGE_ENV, "").strip().lower()
    return raw not in ("0", "false", "no", "off")


# 公网模式引导脚本:页面**不含** token。从 localStorage 取(测试者带外索取后用
# 角落按钮粘贴);只读访客不受打扰(不强制 prompt),写操作才需令牌。纯 DOM 角落
# 按钮,不碰 React 根。app 仍读同一个 ``window.__NTH_CONSOLE_TOKEN__``(本脚本在
# <head> 同步设好,先于 body 里的 bundle 运行)。
_CONSOLE_TOKEN_BOOTSTRAP_JS = (
    '<script>(function(){var K="nth_console_token";'
    'function g(){try{return localStorage.getItem(K)||""}catch(e){return""}}'
    "window.__NTH_CONSOLE_TOKEN__=g()||undefined;"
    'window.nthSetToken=function(t){try{localStorage.setItem(K,t||"")}catch(e){}location.reload()};'
    "window.nthClearToken=function(){try{localStorage.removeItem(K)}catch(e){}location.reload()};"
    'window.addEventListener("DOMContentLoaded",function(){'
    'var b=document.createElement("button");'
    'b.textContent=g()?"\\uD83D\\uDD13 \\u5199\\u5165\\u4ee4\\u724c":"\\uD83D\\uDD11 \\u8bbe\\u7f6e\\u5199\\u5165\\u4ee4\\u724c";'
    'b.style.cssText="position:fixed;right:12px;bottom:12px;z-index:2147483647;'
    "padding:6px 10px;font:12px sans-serif;border:1px solid #888;border-radius:6px;"
    'background:#1c1c1e;color:#eee;cursor:pointer;opacity:.85";'
    'b.onclick=function(){if(g()){if(confirm("\\u6e05\\u9664\\u5df2\\u5b58\\u7684\\u5199\\u5165\\u4ee4\\u724c?"))window.nthClearToken();}'
    'else{var t=prompt("\\u7c98\\u8d34\\u5199\\u5165\\u4ee4\\u724c(\\u5411\\u8fd0\\u8425\\u8005\\u5e26\\u5916\\u7d22\\u53d6):");if(t)window.nthSetToken(t);}};'
    "document.body.appendChild(b);});})();</script>"
)


def _render_console_html(
    index_file: Path, token: str, *, embed_token: bool = True,
) -> str:
    html = index_file.read_text(encoding="utf-8")
    if embed_token:
        snippet = (
            f"<script>window.__NTH_CONSOLE_TOKEN__ = {json.dumps(token)};</script>"
        )
    else:
        snippet = _CONSOLE_TOKEN_BOOTSTRAP_JS   # 页面不含 token
    if "</head>" in html:
        return html.replace("</head>", f"  {snippet}\n  </head>", 1)
    return snippet + html

class _LazyASGIApp:
    """Preserve ``nth_dao.web:app`` without import-time workspace writes."""

    def __init__(self) -> None:
        self._instance: Optional[FastAPI] = None
        self._lock = threading.Lock()

    def _get(self) -> FastAPI:
        instance = self._instance
        if instance is not None:
            return instance
        with self._lock:
            if self._instance is None:
                self._instance = create_app(require_console_auth=True)
            return self._instance

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        await self._get()(scope, receive, send)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get(), name)


app = _LazyASGIApp()


# Remote binding is explicit because federation makes anonymous signed-read
# endpoints reachable beyond this host. Console writes require the operator
# bearer token, and non-loopback HTML responses never embed that token.

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _resolve_safe_bind_host() -> str:
    """Return the host to bind, refusing unsafe configurations.

    Reads NTH_HOST (default 127.0.0.1) and NTH_ALLOW_REMOTE_BIND
    (default unset). When the requested host is not a loopback alias
    and remote bind is not explicitly allowed, raises RuntimeError
    with an actionable error message. Returns the verified host
    string on success.

    The Pydantic-style "fail fast at startup" is intentional: a
    silent fall-through to 127.0.0.1 would mask the operator's intent
    and leave them debugging "why is the dashboard not reachable from
    other machines".
    """
    requested = os.environ.get("NTH_HOST", "127.0.0.1").strip()
    allow_remote = os.environ.get("NTH_ALLOW_REMOTE_BIND", "").strip()

    if requested in _LOOPBACK_HOSTS:
        return requested

    if allow_remote != "1":
        raise RuntimeError(
            f"refusing to bind NTH DAO web console to non-loopback "
            f"host {requested!r}: remote binding exposes federation and "
            f"read-only discovery surfaces to reachable clients. "
            f"Set NTH_ALLOW_REMOTE_BIND=1 only for a trusted LAN or after "
            f"putting an auth proxy / TLS terminator in front of this process, "
            f"or unset NTH_HOST to use the safe loopback default."
        )
    # Loud warning on every cold start so a misconfigured-but-opted-in
    # deployment still surfaces the risk in logs.
    import logging as _logging

    _logging.getLogger("nth_dao.web").warning(
        "NTH DAO web console binding to non-loopback host %r with "
        "NTH_ALLOW_REMOTE_BIND=1; console tokens are not embedded for remote "
        "clients, but federation/read surfaces are network reachable",
        requested,
    )
    return requested


def _repo_git_head() -> str:
    """取本包所在仓库的 HEAD 短哈希 + 是否有未提交改动 —— 进程版本指纹。

    路径从本文件位置反推(不写死),git 跑不通(未装 git/非 editable 安装/
    无 .git)一律降级 ``unknown``,绝不让自检影响服务启动。
    """
    import subprocess

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        head = subprocess.check_output(
            ["git", "-C", pkg_dir, "rev-parse", "--short", "HEAD"],
            text=True, stderr=subprocess.DEVNULL, timeout=5,
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", pkg_dir, "status", "--porcelain"],
            text=True, stderr=subprocess.DEVNULL, timeout=5,
        ).strip()
        return f"{head}{'+dirty' if dirty else ''}"
    except Exception:
        return "unknown"


def _startup_selfcheck(app, host: str, port: int) -> None:
    """启动横幅:打印进程版本指纹 + 路由总数 + 绑定信息。

    解决"JS 重构了、Python 没重启"导致新路由报 405 的漂移:横幅里的
    git HEAD 与 ``git log`` 对不上(或带 ``+dirty``)即说明进程旧了,重启
    即可。整体 try 兜底 —— 自检本身绝不阻断服务启动。
    """
    try:
        routes = [r for r in app.routes if hasattr(r, "methods")]
        head = _repo_git_head()
        print("=" * 56, flush=True)
        print(f"  NTH DAO web  git HEAD = {head}", flush=True)
        print(f"  路由总数 = {len(routes)}", flush=True)
        print(f"  bind http://{host}:{port}", flush=True)
        print("=" * 56, flush=True)
    except Exception:  # 自检失败绝不拖垮启动
        pass


def main() -> None:
    import uvicorn

    host = _resolve_safe_bind_host()
    port = int(os.environ.get("NTH_PORT", "8080"))
    app = create_app(require_console_auth=True)
    _startup_selfcheck(app, host, port)
    uvicorn.run(app, host=host, port=port)


__all__ = ["app", "create_app", "main"]
