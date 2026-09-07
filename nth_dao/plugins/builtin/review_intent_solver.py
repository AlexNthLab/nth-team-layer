"""Offline, review-only reference provider for ``intent.solver``.

This provider performs no model inference and no external retrieval.  It
projects the exact accepted outcomes and constraints into an unsigned proposal
so implementations can exercise the solver boundary without implying that the
proposal is correct, selected, authorized, or executable.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
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
from nth_dao.plugins.intent_solver import (
    INTENT_SOLVER_CAPABILITY_ID,
    INTENT_SOLVER_CONTRACT,
    INTENT_SOLVER_CONTEXT_FORMAT,
    INTENT_SOLVER_INPUT_SCHEMA,
    INTENT_SOLVER_MAX_EVIDENCE,
    INTENT_SOLVER_MAX_PROPOSAL_BYTES,
    INTENT_SOLVER_OUTPUT_SCHEMA,
    SOLVER_PROPOSAL_FORMAT,
    _validate_intent_solver_context_binding_document,
    _validate_intent_solver_exchange_documents,
    _validated_intent_solver_input,
    _validated_intent_solver_output,
    accepted_intent_evidence,
    intent_solver_invocation_context_digest,
    materialized_evidence_descriptor,
    validate_intent_solver_authority,
    validate_intent_solver_input,
    validate_intent_solver_output,
)


REVIEW_INTENT_SOLVER_PLUGIN_ID = "org.nth-dao.intent.review-solver"
REVIEW_INTENT_SOLVER_CLASS = "org.nth-dao.solver.review"

_REVIEWED_ARTIFACT_PATHS = (
    "nth_dao/canonical_json.py",
    "nth_dao/did_key.py",
    "nth_dao/identity.py",
    "nth_dao/plugins/builtin/review_intent_solver.py",
    "nth_dao/plugins/contracts.py",
    "nth_dao/plugins/host.py",
    "nth_dao/plugins/intent_envelope.py",
    "nth_dao/plugins/intent_resolver.py",
    "nth_dao/plugins/intent_solver.py",
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
    return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()


def review_intent_solver_manifest() -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=REVIEW_INTENT_SOLVER_PLUGIN_ID,
        version="1.0.0",
        host_api=PLUGIN_BASE_HOST_API_VERSION,
        kind="intent.solver",
        runtime="builtin",
        provides=(INTENT_SOLVER_CONTRACT,),
        requires=(),
        permissions=(),
        artifact_digest=_reviewed_artifact_digest(),
    )


class ReviewIntentSolverProvider:
    """Thread-safe projection of accepted intent text into a review claim."""

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
        envelope = _validated_intent_solver_input(payload)
        self._validate_context(payload, context)
        context_document = self._context_document(context)
        context_digest = intent_solver_invocation_context_digest(context_document)
        with self._lock:
            if not self._active:
                raise PluginInvocationError("review intent solver is inactive")
            if payload["operation"] == "probe":
                response = self._base_response("probe", context_digest)
            elif payload["operation"] == "propose":
                if envelope is None:
                    raise PluginInvocationError("validated intent envelope is unavailable")
                response = self._propose(
                    payload,
                    context,
                    context_digest,
                    envelope=envelope,
                )
            else:
                raise PluginInvocationError("unsupported intent solver operation")
        proposal = _validated_intent_solver_output(response)
        _validate_intent_solver_exchange_documents(
            payload,
            response,
            envelope=envelope,
            proposal=proposal,
        )
        _validate_intent_solver_context_binding_document(
            response,
            context_document,
            proposal,
        )
        return response

    @staticmethod
    def _validate_context(
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> None:
        if not isinstance(context, PluginInvocationContext):
            raise TypeError("context must be a PluginInvocationContext")
        if context.plugin_id != REVIEW_INTENT_SOLVER_PLUGIN_ID:
            raise PluginInvocationError("intent solver plugin context id mismatch")
        if context.capability_id != INTENT_SOLVER_CAPABILITY_ID:
            raise PluginInvocationError("intent solver capability context mismatch")
        if context.granted_permissions:
            raise PluginInvocationError("review intent solver accepts no permissions")
        validate_intent_solver_authority(payload, context.authority)

    @staticmethod
    def _context_document(context: PluginInvocationContext) -> Dict[str, Any]:
        return {
            "capability_id": context.capability_id,
            "format": INTENT_SOLVER_CONTEXT_FORMAT,
            "idempotency_key": context.authority.idempotency_key,
            "invocation_id": context.invocation_id,
            "mandate_digest": context.authority.mandate_digest,
            "plugin_id": context.plugin_id,
            "principal": context.authority.principal,
            "resource_ids": sorted(context.authority.resource_ids),
        }

    @staticmethod
    def _base_response(operation: str, context_digest: str) -> Dict[str, Any]:
        return {
            "authority": "none",
            "commit_authority": False,
            "detail": "",
            "executable": False,
            "invocation_context_digest": context_digest,
            "max_evidence": INTENT_SOLVER_MAX_EVIDENCE,
            "max_proposal_bytes": INTENT_SOLVER_MAX_PROPOSAL_BYTES,
            "operation": operation,
            "proposal_json": "",
            "proposal_sha256": "",
            "ready": True,
            "status": "",
            "supported_solver_classes": [REVIEW_INTENT_SOLVER_CLASS],
        }

    @classmethod
    def _propose(
        cls,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
        context_digest: str,
        *,
        envelope: Mapping[str, Any],
    ) -> Dict[str, Any]:
        draft = json.loads(envelope["draft_json"])
        evidence = [
            accepted_intent_evidence(
                envelope,
                payload["intent_envelope_digest"],
                observed_at_ms=payload["proposed_at_ms"],
            ),
            *(materialized_evidence_descriptor(item) for item in payload["evidence"]),
        ]
        evidence.sort(key=lambda item: item["digest"])
        review_risk = (
            "This unsigned solver proposal is an unverified claim and requires "
            "deterministic policy evaluation plus explicit selection."
        )
        risks = list(dict.fromkeys([review_risk, *draft["risks"]]))
        proposal = {
            "acceptance_audit_digest": payload["acceptance_audit_digest"],
            "assumptions": list(draft["assumptions"]),
            "authority": "none",
            "claim_status": "unverified",
            "commit_authority": False,
            "constraints": list(draft["constraints"]),
            "created_at_ms": payload["proposed_at_ms"],
            "draft_digest": envelope["draft_digest"],
            "estimates": [],
            "evidence": evidence,
            "executable": False,
            "expires_at_ms": payload["expires_at_ms"],
            "facts": [
                {
                    "evidence_digests": [envelope["draft_digest"]],
                    "statement": (
                        "The proposed actions below are copied from the exact "
                        "signed and accepted IntentDraft outcomes."
                    ),
                }
            ],
            "format": SOLVER_PROPOSAL_FORMAT,
            "intent_envelope_digest": payload["intent_envelope_digest"],
            "policy_snapshot_digest": payload["policy_snapshot_digest"],
            "proposal_id": payload["proposal_id"],
            "proposed_actions": list(draft["outcomes"]),
            "requested_permissions": [],
            "review_required": True,
            "risks": risks,
            "scope_id": envelope["scope_id"],
            "selection_required": True,
            "solver_class": payload["solver_class"],
            "solver_did": "",
            "solver_plugin_id": context.plugin_id,
            "summary": draft["summary"],
            "version": "1",
        }
        proposal_bytes = canonical_json(proposal)
        response = cls._base_response("propose", context_digest)
        response.update(
            {
                "proposal_json": proposal_bytes.decode("utf-8"),
                "proposal_sha256": "sha256:" + hashlib.sha256(proposal_bytes).hexdigest(),
                "status": "proposal",
            }
        )
        return response


class ReviewIntentSolverPlugin:
    def __init__(self) -> None:
        self._provider: Optional[ReviewIntentSolverProvider] = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        if context.plugin_id != REVIEW_INTENT_SOLVER_PLUGIN_ID:
            raise RuntimeError("review intent solver plugin context id mismatch")
        if context.granted_permissions:
            raise PermissionError("review intent solver accepts no host permissions")
        self._provider = ReviewIntentSolverProvider()
        return {INTENT_SOLVER_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        self._provider = None
        if provider is not None:
            provider.deactivate()


def _validate_response_context(
    response: Mapping[str, Any],
    context: PluginInvocationContext,
) -> None:
    proposal = None
    if response.get("operation") == "propose":
        proposal = json.loads(response["proposal_json"])
    _validate_intent_solver_context_binding_document(
        response,
        ReviewIntentSolverProvider._context_document(context),
        proposal,
    )


def _validate_prevalidated_exchange(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> None:
    envelope = proposal = None
    if request.get("operation") == "propose" and response.get("operation") == "propose":
        envelope = json.loads(request["intent_envelope_json"])
        proposal = json.loads(response["proposal_json"])
    _validate_intent_solver_exchange_documents(
        request,
        response,
        envelope=envelope,
        proposal=proposal,
    )


def register_review_intent_solver(host: PluginHost) -> PluginManifest:
    """Install the offline reference solver without enabling it."""

    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    item = review_intent_solver_manifest()
    host.register_builtin(
        item,
        ReviewIntentSolverPlugin,
        allow_manifest_upgrade=True,
        schemas={
            INTENT_SOLVER_CAPABILITY_ID: CapabilitySchemas(
                INTENT_SOLVER_INPUT_SCHEMA,
                INTENT_SOLVER_OUTPUT_SCHEMA,
                input_validator=validate_intent_solver_input,
                output_validator=validate_intent_solver_output,
                exchange_validator=_validate_prevalidated_exchange,
                authority_validator=validate_intent_solver_authority,
                response_context_validator=_validate_response_context,
            )
        },
    )
    return item


__all__ = [
    "REVIEW_INTENT_SOLVER_CLASS",
    "REVIEW_INTENT_SOLVER_PLUGIN_ID",
    "ReviewIntentSolverPlugin",
    "ReviewIntentSolverProvider",
    "register_review_intent_solver",
    "review_intent_solver_manifest",
]
