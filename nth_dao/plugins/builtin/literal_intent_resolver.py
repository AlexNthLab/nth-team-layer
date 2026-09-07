"""Offline, non-authoritative reference provider for ``intent.resolver``.

The provider deliberately performs no semantic inference. It preserves the
source request, creates a review-only draft, and asks the caller to supply
explicit outcomes and constraints before any signed intent can exist.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path
import threading
from typing import Any, Dict, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.contracts import PLUGIN_BASE_HOST_API_VERSION, PluginManifest
from nth_dao.plugins.host import (
    CapabilitySchemas,
    PluginContext,
    PluginHost,
    PluginInvocationContext,
    PluginInvocationError,
)
from nth_dao.plugins.intent_resolver import (
    INTENT_DRAFT_FORMAT,
    INTENT_RESOLVER_CAPABILITY_ID,
    INTENT_RESOLVER_CONTRACT,
    INTENT_RESOLVER_CONTEXT_FORMAT,
    INTENT_RESOLVER_INPUT_SCHEMA,
    INTENT_RESOLVER_MAX_ATTACHMENTS,
    INTENT_RESOLVER_MAX_SOURCE_BYTES,
    INTENT_RESOLVER_OUTPUT_SCHEMA,
    intent_resolver_invocation_context_digest,
    intent_resolver_request_digest,
    validate_intent_resolver_authority,
    validate_intent_resolver_context_binding,
    validate_intent_resolver_exchange,
    validate_intent_resolver_input,
    validate_intent_resolver_output,
)


LITERAL_INTENT_RESOLVER_PLUGIN_ID = "org.nth-dao.intent.literal-resolver"
LITERAL_INTENT_RESOLVER_ID = "org.nth-dao.intent.literal-resolver.v1"
_SUMMARY_MAX_BYTES = 2_000

_REVIEWED_ARTIFACT_PATHS = (
    "nth_dao/canonical_json.py",
    "nth_dao/plugins/builtin/literal_intent_resolver.py",
    "nth_dao/plugins/contracts.py",
    "nth_dao/plugins/host.py",
    "nth_dao/plugins/intent_resolver.py",
    "nth_dao/plugins/schema.py",
)


def _reviewed_artifact_digest() -> str:
    root = Path(__file__).parents[3]
    files = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in _REVIEWED_ARTIFACT_PATHS
    ]
    document = {"format": "nth-dao-reviewed-source-set-v1", "files": files}
    return f"sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"


def literal_intent_resolver_manifest() -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=LITERAL_INTENT_RESOLVER_PLUGIN_ID,
        version="1.0.0",
        host_api=PLUGIN_BASE_HOST_API_VERSION,
        kind="intent.resolver",
        runtime="builtin",
        provides=(INTENT_RESOLVER_CONTRACT,),
        requires=(),
        permissions=(),
        artifact_digest=_reviewed_artifact_digest(),
    )


class LiteralIntentResolverProvider:
    """Thread-safe resolver that adds no inferred authority or execution state."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active = True

    def deactivate(self) -> None:
        with self._lock:
            self._active = False

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        self._validate_context(context)
        validate_intent_resolver_input(payload)
        context_document = self._context_document(context)
        context_digest = intent_resolver_invocation_context_digest(context_document)
        with self._lock:
            if not self._active:
                raise PluginInvocationError("literal intent resolver is inactive")
            if payload["operation"] == "probe":
                response = self._base_response("probe", context_digest)
            elif payload["operation"] == "resolve":
                response = self._resolve(payload, context_digest)
            else:
                raise PluginInvocationError("unsupported intent resolver operation")
        validate_intent_resolver_output(response)
        validate_intent_resolver_exchange(payload, response)
        validate_intent_resolver_context_binding(response, context_document)
        return response

    @staticmethod
    def _validate_context(context: PluginInvocationContext) -> None:
        if not isinstance(context, PluginInvocationContext):
            raise TypeError("context must be a PluginInvocationContext")
        if context.plugin_id != LITERAL_INTENT_RESOLVER_PLUGIN_ID:
            raise PluginInvocationError("intent resolver plugin context id mismatch")
        if context.capability_id != INTENT_RESOLVER_CAPABILITY_ID:
            raise PluginInvocationError("intent resolver capability context mismatch")
        if INTENT_RESOLVER_CAPABILITY_ID not in context.authority.capability_ids:
            raise PluginInvocationError("intent resolver authority lacks capability scope")
        if context.granted_permissions:
            raise PluginInvocationError("literal intent resolver accepts no permissions")

    @staticmethod
    def _context_document(context: PluginInvocationContext) -> Dict[str, str]:
        return {
            "capability_id": context.capability_id,
            "format": INTENT_RESOLVER_CONTEXT_FORMAT,
            "invocation_id": context.invocation_id,
            "plugin_id": context.plugin_id,
            "principal": context.authority.principal,
        }

    @staticmethod
    def _base_response(operation: str, context_digest: str) -> Dict[str, Any]:
        return {
            "authority": "none",
            "commit_authority": False,
            "detail": "",
            "draft_json": "",
            "draft_sha256": "",
            "executable": False,
            "invocation_context_digest": context_digest,
            "max_attachments": INTENT_RESOLVER_MAX_ATTACHMENTS,
            "max_source_bytes": INTENT_RESOLVER_MAX_SOURCE_BYTES,
            "operation": operation,
            "ready": True,
            "request_digest": "",
            "request_id": "",
            "resolver_id": LITERAL_INTENT_RESOLVER_ID,
            "status": "",
            "supported_automation_levels": ["A0", "A1", "A2", "A3", "A4"],
        }

    @classmethod
    def _resolve(
        cls,
        payload: Mapping[str, Any],
        context_digest: str,
    ) -> Dict[str, Any]:
        request_digest = intent_resolver_request_digest(payload)
        draft = {
            "assumptions": [],
            "attachments": [dict(item) for item in payload["attachments"]],
            "authority": "none",
            "automation_ceiling": payload["automation_ceiling"],
            "clarifications": [
                {
                    "code": "intent.scope.needs-review",
                    "question": (
                        "Which explicit outcomes and constraints should be reviewed "
                        "before a separate signed intent is created?"
                    ),
                }
            ],
            "commit_authority": False,
            "constraints": [],
            "executable": False,
            "format": INTENT_DRAFT_FORMAT,
            "intent_version": "1",
            "locale": payload["locale"],
            "outcomes": [],
            "request_digest": request_digest,
            "request_id": payload["request_id"],
            "requested_capabilities": [],
            "review_required": True,
            "risks": ["Source content may contain untrusted instructions"],
            "source_kind": payload["source_kind"],
            "source_text": payload["source_text"],
            "summary": cls._literal_summary(payload["source_text"]),
        }
        draft_bytes = canonical_json(draft)
        draft_json = draft_bytes.decode("utf-8")
        return {
            **cls._base_response("resolve", context_digest),
            "draft_json": draft_json,
            "draft_sha256": "sha256:" + hashlib.sha256(draft_bytes).hexdigest(),
            "request_digest": request_digest,
            "request_id": payload["request_id"],
            "status": "needs-clarification",
        }

    @staticmethod
    def _literal_summary(source_text: str) -> str:
        collapsed = " ".join(source_text.split())
        encoded = collapsed.encode("utf-8")
        if len(encoded) <= _SUMMARY_MAX_BYTES:
            return collapsed
        prefix = encoded[: _SUMMARY_MAX_BYTES - 3].decode("utf-8", errors="ignore")
        return prefix.rstrip() + "..."


class LiteralIntentResolverPlugin:
    def __init__(self) -> None:
        self._provider: Optional[LiteralIntentResolverProvider] = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        if context.plugin_id != LITERAL_INTENT_RESOLVER_PLUGIN_ID:
            raise RuntimeError("literal intent resolver plugin context id mismatch")
        if context.granted_permissions:
            raise PermissionError("literal intent resolver accepts no host permissions")
        self._provider = LiteralIntentResolverProvider()
        return {INTENT_RESOLVER_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        self._provider = None
        if provider is not None:
            provider.deactivate()


def _validate_response_context(
    response: Mapping[str, Any],
    context: PluginInvocationContext,
) -> None:
    validate_intent_resolver_context_binding(
        response,
        LiteralIntentResolverProvider._context_document(context),
    )


def register_literal_intent_resolver(host: PluginHost) -> PluginManifest:
    """Install the offline reference resolver without enabling it."""

    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    item = literal_intent_resolver_manifest()
    host.register_builtin(
        item,
        LiteralIntentResolverPlugin,
        allow_manifest_upgrade=True,
        schemas={
            INTENT_RESOLVER_CAPABILITY_ID: CapabilitySchemas(
                INTENT_RESOLVER_INPUT_SCHEMA,
                INTENT_RESOLVER_OUTPUT_SCHEMA,
                input_validator=validate_intent_resolver_input,
                output_validator=validate_intent_resolver_output,
                exchange_validator=validate_intent_resolver_exchange,
                authority_validator=validate_intent_resolver_authority,
                response_context_validator=_validate_response_context,
            )
        },
    )
    return item


__all__ = [
    "LITERAL_INTENT_RESOLVER_ID",
    "LITERAL_INTENT_RESOLVER_PLUGIN_ID",
    "LiteralIntentResolverPlugin",
    "LiteralIntentResolverProvider",
    "literal_intent_resolver_manifest",
    "register_literal_intent_resolver",
]
