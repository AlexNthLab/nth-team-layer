"""Closed plugin contract for non-authoritative Intent solver proposals.

Solvers receive one cryptographically valid, Host-accepted IntentEnvelope and
may return a reviewable proposal.  A proposal is an unsigned claim: it is not a
policy decision, a capability grant, a Task, a Mission, or execution authority.
The Host binds each live response to the exact invocation and local acceptance
authority before it can be displayed or considered for selection.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field as dataclass_field
import hashlib
import json
import re
import threading
from typing import Any, cast, Dict

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key,
    encode_ed25519_did_key,
    is_prime_order_ed25519_point,
)

from .contracts import CapabilityContract, schema_digest
from .host import InvocationAuthority, PluginAuthorizationError, ProviderBinding
from .intent_acceptance import (
    IntentAcceptancePolicyUnavailable,
    IntentAcceptanceStore,
)
from .intent_envelope import (
    INTENT_ENVELOPE_MAX_DOCUMENT_BYTES,
    IntentEnvelopeError,
    intent_envelope_digest,
)
from .intent_resolver import INTENT_RESOLVER_MAX_SAFE_INTEGER
from .intent_policy_store import IntentPolicyStore
from .schema import PluginSchemaError, validate_instance


INTENT_SOLVER_CAPABILITY_ID = "org.nth-dao.intent.propose"
INTENT_SOLVER_CAPABILITY_VERSION = "1.0.0"
SOLVER_PROPOSAL_FORMAT = "org.nth-dao.solver-proposal"
INTENT_SOLVER_CONTEXT_FORMAT = "org.nth-dao.intent-solver-invocation-context.v1"
INTENT_SOLVER_MAX_DOCUMENT_BYTES = 1_048_576
INTENT_SOLVER_MAX_PROPOSAL_BYTES = 262_144
INTENT_SOLVER_MAX_EVIDENCE = 32
INTENT_SOLVER_MAX_EVIDENCE_ITEM_BYTES = 131_072
INTENT_SOLVER_MAX_EVIDENCE_TOTAL_BYTES = 262_144
INTENT_SOLVER_MAX_ITEMS = 64
INTENT_SOLVER_MAX_TEXT_BYTES = 8_192
INTENT_SOLVER_MAX_TTL_MS = 3_600_000
INTENT_SOLVER_MAX_SAFE_INTEGER = INTENT_RESOLVER_MAX_SAFE_INTEGER

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_MEDIA_TYPE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/"
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$"
)
_EVIDENCE_SOURCE_KINDS = (
    "accepted-intent",
    "artifact",
    "observation",
    "remote-resource",
    "repository",
)
_EVIDENCE_PROVENANCE = (
    "accepted-envelope",
    "invocation-materialized",
    "solver-observed",
)
_EVIDENCE_STATUS = ("content-verified", "signature-bound", "unverified")


class IntentSolverPreparationError(RuntimeError):
    """Trusted local state cannot authorize a governed solver invocation."""


@dataclass(frozen=True, init=False)
class GovernedIntentSolverInvocation:
    """Immutable Host-built request and authority for one solver invocation."""

    _request_json: str
    authority: InvocationAuthority
    acceptance_sequence: int
    policy_snapshot_digest: str
    _acceptance_store: IntentAcceptanceStore = dataclass_field(repr=False, compare=False)
    _policy_store: IntentPolicyStore = dataclass_field(repr=False, compare=False)
    _clock: Callable[[], int] = dataclass_field(repr=False, compare=False)
    _invoke_lock: threading.Lock = dataclass_field(repr=False, compare=False)
    _consumed: bool = dataclass_field(repr=False, compare=False)

    @classmethod
    def _create(
        cls,
        request: Mapping[str, Any],
        authority: InvocationAuthority,
        *,
        acceptance_sequence: int,
        policy_snapshot_digest: str,
        acceptance_store: IntentAcceptanceStore,
        policy_store: IntentPolicyStore,
        clock: Callable[[], int],
    ) -> "GovernedIntentSolverInvocation":
        value = object.__new__(cls)
        object.__setattr__(value, "_request_json", canonical_json(dict(request)).decode("utf-8"))
        object.__setattr__(value, "authority", authority)
        object.__setattr__(value, "acceptance_sequence", acceptance_sequence)
        object.__setattr__(value, "policy_snapshot_digest", policy_snapshot_digest)
        object.__setattr__(value, "_acceptance_store", acceptance_store)
        object.__setattr__(value, "_policy_store", policy_store)
        object.__setattr__(value, "_clock", clock)
        object.__setattr__(value, "_invoke_lock", threading.Lock())
        object.__setattr__(value, "_consumed", False)
        return value

    @property
    def request(self) -> Dict[str, Any]:
        return json.loads(self._request_json)

    def invoke(self, binding: ProviderBinding) -> Dict[str, Any]:
        if not isinstance(binding, ProviderBinding):
            raise TypeError("binding must be a ProviderBinding")
        if binding.contract.digest != INTENT_SOLVER_CONTRACT.digest:
            raise IntentSolverPreparationError(
                "provider binding does not implement the exact intent solver contract"
            )
        with self._invoke_lock:
            if self._consumed:
                raise IntentSolverPreparationError(
                    "governed intent solver invocation has already been consumed"
                )
            request = self.request
            snapshot = _current_governed_solver_snapshot(
                acceptance_store=self._acceptance_store,
                policy_store=self._policy_store,
                envelope_digest=request["intent_envelope_digest"],
                solver_class=request["solver_class"],
                clock=self._clock,
            )
            if (
                snapshot.record.sequence != self.acceptance_sequence
                or snapshot.record.audit_digest != request["acceptance_audit_digest"]
                or snapshot.policy.digest != self.policy_snapshot_digest
                or not request["proposed_at_ms"] <= snapshot.now_ms < request["expires_at_ms"]
            ):
                raise IntentSolverPreparationError(
                    "governed intent solver invocation is stale or expired"
                )
            # Authorization is linearized at this verified snapshot. A later
            # policy change cannot revoke bytes already handed to an in-flight
            # provider, so the ticket is consumed before crossing that boundary.
            object.__setattr__(self, "_consumed", True)
        return binding.invoke(request, authority=self.authority)

_INTEGER_SCHEMA: Dict[str, Any] = {
    "type": "integer",
    "minimum": 0,
    "maximum": INTENT_RESOLVER_MAX_SAFE_INTEGER,
}
_TEXT_LIST_SCHEMA: Dict[str, Any] = {
    "type": "array",
    "maxItems": INTENT_SOLVER_MAX_ITEMS,
    "items": {"type": "string", "minLength": 1, "maxLength": 8_192},
}
_DIGEST_LIST_SCHEMA: Dict[str, Any] = {
    "type": "array",
    "minItems": 1,
    "maxItems": INTENT_SOLVER_MAX_EVIDENCE,
    "items": {"type": "string", "minLength": 71, "maxLength": 71},
}
_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "media_type": {"type": "string", "minLength": 3, "maxLength": 255},
        "observed_at_ms": deepcopy(_INTEGER_SCHEMA),
        "provenance": {"type": "string", "enum": list(_EVIDENCE_PROVENANCE)},
        "source_kind": {"type": "string", "enum": list(_EVIDENCE_SOURCE_KINDS)},
        "source_ref": {"type": "string", "minLength": 1, "maxLength": 2_048},
        "verification_status": {"type": "string", "enum": list(_EVIDENCE_STATUS)},
    },
    "required": [
        "digest",
        "media_type",
        "observed_at_ms",
        "provenance",
        "source_kind",
        "source_ref",
        "verification_status",
    ],
}
_MATERIALIZED_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        **deepcopy(_EVIDENCE_SCHEMA["properties"]),
        "content_base64": {
            "type": "string",
            "maxLength": ((INTENT_SOLVER_MAX_EVIDENCE_ITEM_BYTES + 2) // 3) * 4,
        },
    },
    "required": sorted([*_EVIDENCE_SCHEMA["required"], "content_base64"]),
}
_FACT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "evidence_digests": deepcopy(_DIGEST_LIST_SCHEMA),
        "statement": {"type": "string", "minLength": 1, "maxLength": 8_192},
    },
    "required": ["evidence_digests", "statement"],
}
_ESTIMATE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "basis": {"type": "string", "minLength": 1, "maxLength": 8_192},
        "evidence_digests": deepcopy(_DIGEST_LIST_SCHEMA),
        "statement": {"type": "string", "minLength": 1, "maxLength": 8_192},
    },
    "required": ["basis", "evidence_digests", "statement"],
}

SOLVER_PROPOSAL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "acceptance_audit_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "assumptions": deepcopy(_TEXT_LIST_SCHEMA),
        "authority": {"type": "string", "enum": ["none"]},
        "claim_status": {"type": "string", "enum": ["unverified"]},
        "commit_authority": {"type": "boolean", "enum": [False]},
        "constraints": deepcopy(_TEXT_LIST_SCHEMA),
        "created_at_ms": deepcopy(_INTEGER_SCHEMA),
        "draft_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "estimates": {
            "type": "array",
            "maxItems": INTENT_SOLVER_MAX_ITEMS,
            "items": deepcopy(_ESTIMATE_SCHEMA),
        },
        "evidence": {
            "type": "array",
            "minItems": 1,
            "maxItems": INTENT_SOLVER_MAX_EVIDENCE + 1,
            "items": deepcopy(_EVIDENCE_SCHEMA),
        },
        "executable": {"type": "boolean", "enum": [False]},
        "expires_at_ms": deepcopy(_INTEGER_SCHEMA),
        "facts": {
            "type": "array",
            "minItems": 1,
            "maxItems": INTENT_SOLVER_MAX_ITEMS,
            "items": deepcopy(_FACT_SCHEMA),
        },
        "format": {"type": "string", "enum": [SOLVER_PROPOSAL_FORMAT]},
        "intent_envelope_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "policy_snapshot_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "proposal_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "proposed_actions": {
            "type": "array",
            "minItems": 1,
            "maxItems": INTENT_SOLVER_MAX_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": 8_192},
        },
        "requested_permissions": {
            "type": "array",
            "maxItems": INTENT_SOLVER_MAX_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": 256},
        },
        "review_required": {"type": "boolean", "enum": [True]},
        "risks": {
            "type": "array",
            "minItems": 1,
            "maxItems": INTENT_SOLVER_MAX_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": 8_192},
        },
        "scope_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "selection_required": {"type": "boolean", "enum": [True]},
        "solver_class": {"type": "string", "minLength": 1, "maxLength": 256},
        "solver_did": {"type": "string", "maxLength": 128},
        "solver_plugin_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "summary": {"type": "string", "minLength": 1, "maxLength": 8_192},
        "version": {"type": "string", "enum": ["1"]},
    },
    "required": [
        "acceptance_audit_digest",
        "assumptions",
        "authority",
        "claim_status",
        "commit_authority",
        "constraints",
        "created_at_ms",
        "draft_digest",
        "estimates",
        "evidence",
        "executable",
        "expires_at_ms",
        "facts",
        "format",
        "intent_envelope_digest",
        "policy_snapshot_digest",
        "proposal_id",
        "proposed_actions",
        "requested_permissions",
        "review_required",
        "risks",
        "scope_id",
        "selection_required",
        "solver_class",
        "solver_did",
        "solver_plugin_id",
        "summary",
        "version",
    ],
}

INTENT_SOLVER_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "acceptance_audit_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "evidence": {
            "type": "array",
            "maxItems": INTENT_SOLVER_MAX_EVIDENCE,
            "items": deepcopy(_MATERIALIZED_EVIDENCE_SCHEMA),
        },
        "expires_at_ms": deepcopy(_INTEGER_SCHEMA),
        "intent_envelope_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "intent_envelope_json": {
            "type": "string",
            "maxLength": INTENT_ENVELOPE_MAX_DOCUMENT_BYTES,
        },
        "operation": {"type": "string", "enum": ["probe", "propose"]},
        "policy_snapshot_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "proposal_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "proposed_at_ms": deepcopy(_INTEGER_SCHEMA),
        "solver_class": {"type": "string", "minLength": 1, "maxLength": 256},
    },
    "required": ["operation"],
}

INTENT_SOLVER_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "authority": {"type": "string", "enum": ["none"]},
        "commit_authority": {"type": "boolean", "enum": [False]},
        "detail": {"type": "string", "maxLength": 2_048},
        "executable": {"type": "boolean", "enum": [False]},
        "invocation_context_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "max_evidence": {
            "type": "integer",
            "minimum": 1,
            "maximum": INTENT_SOLVER_MAX_SAFE_INTEGER,
        },
        "max_proposal_bytes": {
            "type": "integer",
            "minimum": 1,
            "maximum": INTENT_SOLVER_MAX_SAFE_INTEGER,
        },
        "operation": {"type": "string", "enum": ["probe", "propose"]},
        "proposal_json": {"type": "string", "maxLength": INTENT_SOLVER_MAX_PROPOSAL_BYTES},
        "proposal_sha256": {"type": "string", "maxLength": 71},
        "ready": {"type": "boolean"},
        "status": {"type": "string", "enum": ["", "proposal"]},
        "supported_solver_classes": {
            "type": "array",
            "minItems": 1,
            "maxItems": 16,
            "items": {"type": "string", "minLength": 1, "maxLength": 256},
        },
    },
    "required": [
        "authority",
        "commit_authority",
        "detail",
        "executable",
        "invocation_context_digest",
        "max_evidence",
        "max_proposal_bytes",
        "operation",
        "proposal_json",
        "proposal_sha256",
        "ready",
        "status",
        "supported_solver_classes",
    ],
}

INTENT_SOLVER_CONTRACT = CapabilityContract(
    capability_id=INTENT_SOLVER_CAPABILITY_ID,
    version=INTENT_SOLVER_CAPABILITY_VERSION,
    input_schema_digest=schema_digest(INTENT_SOLVER_INPUT_SCHEMA),
    output_schema_digest=schema_digest(INTENT_SOLVER_OUTPUT_SCHEMA),
    effects=("none",),
    consistency="C0",
    privacy="confidential",
    security="untrusted-hint",
    cardinality="many",
    deterministic=False,
    retention="none",
    failure_semantics="retry-safe",
)


def _document_size(value: Mapping[str, Any], *, path: str, maximum: int) -> None:
    try:
        size = len(canonical_json(dict(value)))
    except (TypeError, ValueError, RecursionError):
        raise PluginSchemaError(f"{path} is not bounded canonical JSON data") from None
    if size > maximum:
        raise PluginSchemaError(f"{path} exceeds the UTF-8 byte limit")


def _hash(value: Any, *, path: str) -> None:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise PluginSchemaError(f"{path} must be a lowercase SHA-256 content address")


def _identifier(value: Any, *, path: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise PluginSchemaError(f"{path} must be a bounded exact identifier")


def _text(
    value: Any,
    *,
    path: str,
    maximum_bytes: int = INTENT_SOLVER_MAX_TEXT_BYTES,
    multiline: bool = True,
) -> None:
    if not isinstance(value, str) or not value.strip():
        raise PluginSchemaError(f"{path} must be non-empty text")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise PluginSchemaError(f"{path} exceeds the UTF-8 byte limit")
    allowed = {0x09, 0x0A, 0x0D} if multiline else set()
    if any(
        (ord(char) < 0x20 and ord(char) not in allowed) or ord(char) == 0x7F
        for char in value
    ):
        raise PluginSchemaError(f"{path} contains forbidden control characters")


def _did_or_empty(value: Any, *, path: str) -> None:
    if value == "":
        return
    if not isinstance(value, str):
        raise PluginSchemaError(f"{path} must be empty or a canonical Ed25519 did:key")
    try:
        public_key = decode_ed25519_did_key(value)
        if (
            encode_ed25519_did_key(public_key) != value
            or not is_prime_order_ed25519_point(public_key)
        ):
            raise PluginSchemaError(f"{path} is not canonical")
    except DIDKeyError:
        raise PluginSchemaError(f"{path} must be empty or a canonical Ed25519 did:key") from None


def canonical_signed_intent_envelope(value: str) -> tuple[Dict[str, Any], bytes, str]:
    """Parse canonical signed Envelope JSON and verify its detached signature."""

    if not isinstance(value, str):
        raise ValueError("intent_envelope_json must be text")
    encoded = value.encode("utf-8")
    if len(encoded) > INTENT_ENVELOPE_MAX_DOCUMENT_BYTES:
        raise ValueError("intent_envelope_json exceeds the UTF-8 byte limit")
    try:
        document = json.loads(value)
        if type(document) is not dict:
            raise ValueError
        digest = intent_envelope_digest(document)
        canonical = canonical_json(document)
    except ImportError:
        raise
    except (IntentEnvelopeError, TypeError, ValueError, RecursionError):
        raise ValueError("intent_envelope_json is not a valid signed IntentEnvelope") from None
    if canonical != encoded:
        raise ValueError("intent_envelope_json must use canonical JSON encoding")
    return document, canonical, digest


def _validate_evidence(value: Mapping[str, Any], *, path: str) -> None:
    _hash(value["digest"], path=f"{path}.digest")
    if _MEDIA_TYPE_RE.fullmatch(value["media_type"]) is None:
        raise PluginSchemaError(f"{path}.media_type is invalid")
    _text(
        value["source_ref"],
        path=f"{path}.source_ref",
        maximum_bytes=2_048,
        multiline=False,
    )
    provenance = value["provenance"]
    status = value["verification_status"]
    source_kind = value["source_kind"]
    expected = {
        "accepted-envelope": ("accepted-intent", "signature-bound"),
        "invocation-materialized": (None, "content-verified"),
        "solver-observed": (None, "unverified"),
    }[provenance]
    if status != expected[1] or (expected[0] is not None and source_kind != expected[0]):
        raise PluginSchemaError(f"{path} provenance and verification status conflict")
    if provenance != "accepted-envelope" and source_kind == "accepted-intent":
        raise PluginSchemaError(f"{path} accepted-intent evidence must be envelope-bound")
    if provenance == "accepted-envelope" and _HASH_RE.fullmatch(value["source_ref"]) is None:
        raise PluginSchemaError(f"{path}.source_ref must bind the IntentEnvelope digest")


def _validated_evidence_list(
    values: Any,
    *,
    path: str,
    allowed_provenance: frozenset[str] | None = None,
) -> list[dict]:
    digests = []
    for index, item in enumerate(values):
        _validate_evidence(item, path=f"{path}[{index}]")
        if allowed_provenance is not None and item["provenance"] not in allowed_provenance:
            raise PluginSchemaError(f"{path}[{index}] provenance is not allowed here")
        digests.append(item["digest"])
    if digests != sorted(set(digests)):
        raise PluginSchemaError(f"{path} must have unique entries sorted by digest")
    return [dict(item) for item in values]


def materialized_evidence_descriptor(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Strip invocation-only bytes from one validated evidence material."""

    return {field: deepcopy(value[field]) for field in _EVIDENCE_SCHEMA["required"]}


def _validated_materialized_evidence_list(values: Any, *, path: str) -> list[dict]:
    digests: list[str] = []
    total_bytes = 0
    for index, item in enumerate(values):
        item_path = f"{path}[{index}]"
        _validate_evidence(item, path=item_path)
        if item["provenance"] != "invocation-materialized":
            raise PluginSchemaError(f"{item_path} provenance is not allowed here")
        encoded = item["content_base64"]
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise PluginSchemaError(f"{item_path}.content_base64 is not canonical Base64") from None
        if base64.b64encode(content).decode("ascii") != encoded:
            raise PluginSchemaError(f"{item_path}.content_base64 is not canonical Base64")
        if len(content) > INTENT_SOLVER_MAX_EVIDENCE_ITEM_BYTES:
            raise PluginSchemaError(f"{item_path} exceeds the evidence byte limit")
        expected = "sha256:" + hashlib.sha256(content).hexdigest()
        if item["digest"] != expected:
            raise PluginSchemaError(f"{item_path}.digest does not bind materialized content")
        total_bytes += len(content)
        if total_bytes > INTENT_SOLVER_MAX_EVIDENCE_TOTAL_BYTES:
            raise PluginSchemaError(f"{path} exceeds the aggregate evidence byte limit")
        digests.append(item["digest"])
    if digests != sorted(set(digests)):
        raise PluginSchemaError(f"{path} must have unique entries sorted by digest")
    return [dict(item) for item in values]


def accepted_intent_evidence(
    envelope: Mapping[str, Any],
    envelope_digest: str,
    *,
    observed_at_ms: int,
) -> Dict[str, Any]:
    """Return the sole protocol-defined evidence item derived from an Envelope."""

    return {
        "digest": envelope["draft_digest"],
        "media_type": "application/vnd.nth-dao.intent-draft+json",
        "observed_at_ms": observed_at_ms,
        "provenance": "accepted-envelope",
        "source_kind": "accepted-intent",
        "source_ref": envelope_digest,
        "verification_status": "signature-bound",
    }


def _validated_intent_solver_input(
    value: Mapping[str, Any],
) -> Dict[str, Any] | None:
    if not isinstance(value, Mapping):
        raise PluginSchemaError("$input must be an object")
    _document_size(value, path="$input", maximum=INTENT_SOLVER_MAX_DOCUMENT_BYTES)
    validate_instance(value, INTENT_SOLVER_INPUT_SCHEMA, path="$input")
    if value.get("operation") == "probe":
        if set(value) != {"operation"}:
            raise PluginSchemaError("$input probe accepts only operation")
        return None
    if value.get("operation") != "propose":
        raise PluginSchemaError("$input.operation is unsupported")
    required = set(INTENT_SOLVER_INPUT_SCHEMA["properties"])
    if set(value) != required:
        raise PluginSchemaError("$input propose has missing or unknown fields")
    _identifier(value["proposal_id"], path="$input.proposal_id")
    _identifier(value["solver_class"], path="$input.solver_class")
    for field in ("intent_envelope_digest", "acceptance_audit_digest", "policy_snapshot_digest"):
        _hash(value[field], path=f"$input.{field}")
    try:
        envelope, _encoded, envelope_digest = canonical_signed_intent_envelope(
            value["intent_envelope_json"]
        )
    except ValueError as exc:
        raise PluginSchemaError(f"$input.intent_envelope_json {exc}") from None
    if value["intent_envelope_digest"] != envelope_digest:
        raise PluginSchemaError("$input.intent_envelope_digest does not bind the signed envelope")
    if value["solver_class"] not in envelope["solver_classes"]:
        raise PluginSchemaError("$input.solver_class is not allowed by the signed envelope")
    proposed_at = value["proposed_at_ms"]
    expires_at = value["expires_at_ms"]
    if not (
        envelope["issued_at_ms"] <= proposed_at < expires_at <= envelope["expires_at_ms"]
        and expires_at - proposed_at <= INTENT_SOLVER_MAX_TTL_MS
    ):
        raise PluginSchemaError("$input proposal validity is outside the signed envelope or wire TTL")
    evidence = _validated_materialized_evidence_list(
        value["evidence"],
        path="$input.evidence",
    )
    if any(item["observed_at_ms"] > proposed_at for item in evidence):
        raise PluginSchemaError("$input.evidence cannot be observed after proposed_at_ms")
    if envelope["draft_digest"] in {item["digest"] for item in evidence}:
        raise PluginSchemaError("$input.evidence duplicates accepted IntentDraft evidence")
    return envelope


def validate_intent_solver_input(value: Mapping[str, Any]) -> None:
    """Validate one closed probe or governed proposal request."""

    _validated_intent_solver_input(value)


def validate_intent_solver_authority(
    request: Mapping[str, Any],
    authority: InvocationAuthority,
) -> None:
    """Require exact Host authority binding for one proposal invocation."""

    if not isinstance(authority, InvocationAuthority):
        raise PluginAuthorizationError("intent solver requires local invocation authority")
    if INTENT_SOLVER_CAPABILITY_ID not in authority.capability_ids:
        raise PluginAuthorizationError("intent solver authority lacks capability scope")
    if request.get("operation") == "probe":
        if authority.mandate_digest or authority.idempotency_key or authority.resource_ids:
            raise PluginAuthorizationError(
                "intent solver probe must not carry business authority"
            )
        return
    if authority.mandate_digest != request.get("acceptance_audit_digest"):
        raise PluginAuthorizationError(
            "intent solver authority does not bind acceptance audit"
        )
    if authority.idempotency_key != request.get("proposal_id"):
        raise PluginAuthorizationError(
            "intent solver authority does not bind proposal idempotency"
        )
    evidence_digests = {
        item["digest"] for item in request.get("evidence", []) if isinstance(item, Mapping)
    }
    expected_resources = {
        request.get("intent_envelope_digest"),
        request.get("policy_snapshot_digest"),
        *evidence_digests,
    }
    if None in expected_resources or authority.resource_ids != frozenset(expected_resources):
        raise PluginAuthorizationError(
            "intent solver authority resources do not exactly bind input evidence"
        )


@dataclass(frozen=True)
class _GovernedSolverSnapshot:
    record: Any
    policy: Any
    envelope: Dict[str, Any]
    now_ms: int


def _current_governed_solver_snapshot(
    *,
    acceptance_store: IntentAcceptanceStore,
    policy_store: IntentPolicyStore,
    envelope_digest: str,
    solver_class: str,
    clock: Callable[[], int],
) -> _GovernedSolverSnapshot:
    """Resolve one current governed state at a policy-lock linearization point."""

    if type(acceptance_store) is not IntentAcceptanceStore:
        raise TypeError("acceptance_store must be an IntentAcceptanceStore")
    if type(policy_store) is not IntentPolicyStore:
        raise TypeError("policy_store must be an IntentPolicyStore")
    if not callable(clock):
        raise TypeError("clock must be a trusted callable")
    try:
        checked_policy_store = cast(
            IntentPolicyStore,
            acceptance_store._require_local_policy_store(policy_store),
        )
    except IntentAcceptancePolicyUnavailable:
        raise IntentSolverPreparationError(
            "acceptance and policy stores must belong to the same workspace"
        ) from None
    with checked_policy_store.coordination_lock():
        now_ms = clock()
        if type(now_ms) is not int or not 0 <= now_ms <= INTENT_SOLVER_MAX_SAFE_INTEGER:
            raise IntentSolverPreparationError("trusted clock returned an invalid timestamp")
        record, current_acceptance = acceptance_store._lookup_with_scope_head(
            envelope_digest
        )
        if record is None:
            raise IntentSolverPreparationError(
                "accepted IntentEnvelope is not in the verified journal"
            )
        try:
            envelope = record.envelope
            context = json.loads(record.context_json)
            authorization_digest = context["authorization_digest"]
            allowed_solver_classes = context["allowed_solver_classes"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise IntentSolverPreparationError(
                "accepted intent governance context is invalid"
            ) from None
        if not authorization_digest:
            raise IntentSolverPreparationError(
                "legacy ungoverned acceptance cannot invoke a solver"
            )
        if (
            current_acceptance is None
            or current_acceptance.envelope_digest != record.envelope_digest
        ):
            raise IntentSolverPreparationError(
                "accepted IntentEnvelope is no longer the current scope head"
            )
        policy = checked_policy_store._current_unlocked(
            envelope["audience_did"],
            envelope["scope_id"],
        )
        if policy is None or policy.digest != authorization_digest:
            raise IntentSolverPreparationError(
                "acceptance policy is no longer the current scope head"
            )
        if not policy.is_valid_at(now_ms):
            raise IntentSolverPreparationError("acceptance policy is not currently valid")
        if record.accepted_at_ms > now_ms:
            raise IntentSolverPreparationError(
                "acceptance observation is later than the trusted clock"
            )
        if not envelope["issued_at_ms"] <= now_ms < envelope["expires_at_ms"]:
            raise IntentSolverPreparationError(
                "accepted IntentEnvelope is not currently valid"
            )
        if solver_class not in allowed_solver_classes:
            raise IntentSolverPreparationError(
                "solver class is outside the governed acceptance"
            )
        return _GovernedSolverSnapshot(
            record=record,
            policy=policy,
            envelope=envelope,
            now_ms=now_ms,
        )


def prepare_governed_intent_solver_invocation(
    *,
    acceptance_store: IntentAcceptanceStore,
    policy_store: IntentPolicyStore,
    envelope_digest: str,
    proposal_id: str,
    solver_class: str,
    evidence: Sequence[Mapping[str, Any]] = (),
    clock: Callable[[], int],
    ttl_ms: int = 300_000,
) -> GovernedIntentSolverInvocation:
    """Build a solver invocation only from current verified local state."""

    if type(acceptance_store) is not IntentAcceptanceStore:
        raise TypeError("acceptance_store must be an IntentAcceptanceStore")
    if type(policy_store) is not IntentPolicyStore:
        raise TypeError("policy_store must be an IntentPolicyStore")
    if not callable(clock):
        raise TypeError("clock must be a trusted callable")
    if type(ttl_ms) is not int or not 1 <= ttl_ms <= INTENT_SOLVER_MAX_TTL_MS:
        raise ValueError("ttl_ms must be within the solver wire TTL")
    if not isinstance(evidence, (list, tuple)):
        raise TypeError("evidence must be a list or tuple")
    snapshot = _current_governed_solver_snapshot(
        acceptance_store=acceptance_store,
        policy_store=policy_store,
        envelope_digest=envelope_digest,
        solver_class=solver_class,
        clock=clock,
    )
    now_ms = snapshot.now_ms
    record = snapshot.record
    envelope = snapshot.envelope
    policy = snapshot.policy
    expires_at_ms = min(
        now_ms + ttl_ms,
        envelope["expires_at_ms"],
        policy.to_dict()["expires_at_ms"],
    )
    if expires_at_ms <= now_ms:
        raise IntentSolverPreparationError("no positive proposal validity remains")
    try:
        evidence_items = [deepcopy(dict(item)) for item in evidence]
    except (TypeError, ValueError):
        raise TypeError("evidence entries must be mappings") from None
    request = {
        "acceptance_audit_digest": record.audit_digest,
        "evidence": evidence_items,
        "expires_at_ms": expires_at_ms,
        "intent_envelope_digest": record.envelope_digest,
        "intent_envelope_json": record.envelope_json,
        "operation": "propose",
        "policy_snapshot_digest": policy.digest,
        "proposal_id": proposal_id,
        "proposed_at_ms": now_ms,
        "solver_class": solver_class,
    }
    validate_intent_solver_input(request)
    resources = {
        record.envelope_digest,
        policy.digest,
        *(item["digest"] for item in evidence_items),
    }
    authority = InvocationAuthority(
        principal=envelope["audience_did"],
        capability_ids=frozenset({INTENT_SOLVER_CAPABILITY_ID}),
        mandate_digest=record.audit_digest,
        idempotency_key=proposal_id,
        resource_ids=frozenset(resources),
    )
    validate_intent_solver_authority(request, authority)
    return GovernedIntentSolverInvocation._create(
        request,
        authority,
        acceptance_sequence=record.sequence,
        policy_snapshot_digest=policy.digest,
        acceptance_store=acceptance_store,
        policy_store=policy_store,
        clock=clock,
    )


def intent_solver_invocation_context_digest(value: Mapping[str, Any]) -> str:
    """Content-address the exact Host invocation and acceptance authority."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$context must be an object")
    required = {
        "capability_id",
        "format",
        "idempotency_key",
        "invocation_id",
        "mandate_digest",
        "plugin_id",
        "principal",
        "resource_ids",
    }
    if set(value) != required:
        raise PluginSchemaError("$context has missing or unknown fields")
    if value["format"] != INTENT_SOLVER_CONTEXT_FORMAT:
        raise PluginSchemaError("$context.format is invalid")
    for field in ("capability_id", "invocation_id", "plugin_id"):
        _identifier(value[field], path=f"$context.{field}")
    if value["capability_id"] != INTENT_SOLVER_CAPABILITY_ID:
        raise PluginSchemaError("$context.capability_id is invalid")
    _text(
        value["principal"],
        path="$context.principal",
        maximum_bytes=512,
        multiline=False,
    )
    if value["mandate_digest"]:
        _hash(value["mandate_digest"], path="$context.mandate_digest")
    if value["idempotency_key"]:
        _identifier(value["idempotency_key"], path="$context.idempotency_key")
    resources = value["resource_ids"]
    if type(resources) is not list or len(resources) > INTENT_SOLVER_MAX_EVIDENCE + 2:
        raise PluginSchemaError("$context.resource_ids must be a bounded list")
    for index, item in enumerate(resources):
        _hash(item, path=f"$context.resource_ids[{index}]")
    if resources != sorted(set(resources)):
        raise PluginSchemaError("$context.resource_ids must be sorted and unique")
    document = dict(value)
    return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()


def _validate_intent_solver_context_binding_document(
    response: Mapping[str, Any],
    context: Mapping[str, Any],
    proposal: Mapping[str, Any] | None,
) -> None:
    expected = intent_solver_invocation_context_digest(context)
    if response.get("invocation_context_digest") != expected:
        raise PluginSchemaError(
            "$output.invocation_context_digest does not bind Host invocation context"
        )
    if response.get("operation") == "propose":
        if proposal is None:
            raise PluginSchemaError("$output proposal is unavailable for context binding") from None
        if proposal["solver_plugin_id"] != context["plugin_id"]:
            raise PluginSchemaError("$proposal.solver_plugin_id does not bind Host plugin context")


def validate_intent_solver_context_binding(
    response: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    proposal = None
    if response.get("operation") == "propose":
        try:
            proposal, _canonical = canonical_solver_proposal(response["proposal_json"])
        except (KeyError, TypeError, ValueError):
            raise PluginSchemaError(
                "$output proposal is unavailable for context binding"
            ) from None
    _validate_intent_solver_context_binding_document(response, context, proposal)


def canonical_solver_proposal(value: str) -> tuple[Dict[str, Any], bytes]:
    """Parse and validate one canonical, unsigned SolverProposal."""

    if not isinstance(value, str):
        raise ValueError("proposal_json must be text")
    encoded = value.encode("utf-8")
    if len(encoded) > INTENT_SOLVER_MAX_PROPOSAL_BYTES:
        raise ValueError("proposal_json exceeds the UTF-8 byte limit")
    try:
        document = json.loads(value)
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("proposal_json must contain valid JSON") from None
    if type(document) is not dict:
        raise ValueError("proposal_json must contain an object")
    validate_solver_proposal(document)
    canonical = canonical_json(document)
    if canonical != encoded:
        raise ValueError("proposal_json must use canonical JSON encoding")
    return document, canonical


def solver_proposal_digest(value: str) -> str:
    _document, canonical = canonical_solver_proposal(value)
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def validate_solver_proposal(value: Mapping[str, Any]) -> None:
    """Validate closed claim semantics without asserting that claims are true."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$proposal must be an object")
    _document_size(value, path="$proposal", maximum=INTENT_SOLVER_MAX_PROPOSAL_BYTES)
    validate_instance(value, SOLVER_PROPOSAL_SCHEMA, path="$proposal")
    for field in ("proposal_id", "scope_id", "solver_class", "solver_plugin_id"):
        _identifier(value[field], path=f"$proposal.{field}")
    _did_or_empty(value["solver_did"], path="$proposal.solver_did")
    for field in (
        "acceptance_audit_digest",
        "draft_digest",
        "intent_envelope_digest",
        "policy_snapshot_digest",
    ):
        _hash(value[field], path=f"$proposal.{field}")
    if not value["created_at_ms"] < value["expires_at_ms"]:
        raise PluginSchemaError("$proposal validity must be positive")
    if value["expires_at_ms"] - value["created_at_ms"] > INTENT_SOLVER_MAX_TTL_MS:
        raise PluginSchemaError("$proposal validity exceeds the wire TTL")
    for field in ("summary",):
        _text(value[field], path=f"$proposal.{field}")
    for field in ("assumptions", "constraints", "proposed_actions", "risks"):
        for index, item in enumerate(value[field]):
            _text(item, path=f"$proposal.{field}[{index}]")
    permissions = value["requested_permissions"]
    if permissions != sorted(set(permissions)):
        raise PluginSchemaError("$proposal.requested_permissions must be sorted and unique")
    for index, permission in enumerate(permissions):
        _identifier(permission, path=f"$proposal.requested_permissions[{index}]")
    evidence = _validated_evidence_list(value["evidence"], path="$proposal.evidence")
    if any(item["observed_at_ms"] > value["created_at_ms"] for item in evidence):
        raise PluginSchemaError("$proposal evidence cannot be observed after creation")
    evidence_digests = {item["digest"] for item in evidence}
    accepted = [item for item in evidence if item["provenance"] == "accepted-envelope"]
    if len(accepted) != 1:
        raise PluginSchemaError("$proposal must contain exactly one accepted IntentDraft evidence item")
    if (
        accepted[0]["digest"] != value["draft_digest"]
        or accepted[0]["source_ref"] != value["intent_envelope_digest"]
    ):
        raise PluginSchemaError("$proposal accepted evidence does not bind its draft and envelope")
    referenced: set[str] = set()
    statements: list[str] = []
    for collection_name in ("facts", "estimates"):
        for index, item in enumerate(value[collection_name]):
            _text(item["statement"], path=f"$proposal.{collection_name}[{index}].statement")
            statements.append(item["statement"])
            if collection_name == "estimates":
                _text(item["basis"], path=f"$proposal.estimates[{index}].basis")
            digests = item["evidence_digests"]
            if digests != sorted(set(digests)):
                raise PluginSchemaError(
                    f"$proposal.{collection_name}[{index}].evidence_digests must be sorted and unique"
                )
            for digest in digests:
                _hash(digest, path=f"$proposal.{collection_name}[{index}].evidence_digests")
                if digest not in evidence_digests:
                    raise PluginSchemaError(
                        f"$proposal.{collection_name}[{index}] references unknown evidence"
                    )
                referenced.add(digest)
    if len(statements) != len(set(statements)):
        raise PluginSchemaError("$proposal fact and estimate statements must be unique")
    if value["draft_digest"] not in referenced:
        raise PluginSchemaError("$proposal facts must reference the accepted IntentDraft evidence")


def _validated_intent_solver_output(
    value: Mapping[str, Any],
) -> Dict[str, Any] | None:
    if not isinstance(value, Mapping):
        raise PluginSchemaError("$output must be an object")
    _document_size(value, path="$output", maximum=INTENT_SOLVER_MAX_DOCUMENT_BYTES)
    validate_instance(value, INTENT_SOLVER_OUTPUT_SCHEMA, path="$output")
    supported = value["supported_solver_classes"]
    if supported != sorted(set(supported)):
        raise PluginSchemaError("$output supported solver classes must be sorted and unique")
    for index, item in enumerate(supported):
        _identifier(item, path=f"$output.supported_solver_classes[{index}]")
    if value["max_evidence"] > INTENT_SOLVER_MAX_EVIDENCE:
        raise PluginSchemaError("$output max_evidence exceeds the wire limit")
    if value["max_proposal_bytes"] > INTENT_SOLVER_MAX_PROPOSAL_BYTES:
        raise PluginSchemaError("$output max_proposal_bytes exceeds the wire limit")
    if not value["ready"] or value["detail"]:
        raise PluginSchemaError("$output reference operation must be ready without detail")
    _hash(value["invocation_context_digest"], path="$output.invocation_context_digest")
    if value["operation"] == "probe":
        if value["proposal_json"] or value["proposal_sha256"] or value["status"]:
            raise PluginSchemaError("$output probe cannot carry proposal state")
        return None
    if value["operation"] != "propose":
        raise PluginSchemaError("$output.operation is unsupported")
    try:
        proposal, canonical = canonical_solver_proposal(value["proposal_json"])
    except ValueError as exc:
        raise PluginSchemaError(f"$output.proposal_json {exc}") from None
    expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if value["proposal_sha256"] != expected:
        raise PluginSchemaError("$output.proposal_sha256 does not bind proposal_json")
    if value["status"] != "proposal":
        raise PluginSchemaError("$output.status must identify a proposal")
    return proposal


def validate_intent_solver_output(value: Mapping[str, Any]) -> None:
    """Validate one provider response and its canonical proposal address."""

    _validated_intent_solver_output(value)


def _validate_intent_solver_exchange_documents(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    *,
    envelope: Mapping[str, Any] | None,
    proposal: Mapping[str, Any] | None,
) -> None:
    if response.get("operation") != request.get("operation"):
        raise PluginSchemaError("$output.operation does not match $input.operation")
    if request.get("operation") == "probe":
        return
    if request.get("solver_class") not in response.get("supported_solver_classes", []):
        raise PluginSchemaError("$output does not support the requested solver class")
    if proposal is None or envelope is None:
        raise PluginSchemaError("$output proposal or input envelope is unavailable for exchange binding") from None
    envelope_digest = request["intent_envelope_digest"]
    bindings = {
        "acceptance_audit_digest": request["acceptance_audit_digest"],
        "created_at_ms": request["proposed_at_ms"],
        "expires_at_ms": request["expires_at_ms"],
        "intent_envelope_digest": envelope_digest,
        "policy_snapshot_digest": request["policy_snapshot_digest"],
        "proposal_id": request["proposal_id"],
        "solver_class": request["solver_class"],
    }
    for field, expected in bindings.items():
        if proposal[field] != expected:
            raise PluginSchemaError(f"$proposal.{field} does not bind $input")
    for field in ("draft_digest", "scope_id"):
        if proposal[field] != envelope[field]:
            raise PluginSchemaError(f"$proposal.{field} does not bind the signed envelope")
    draft = json.loads(envelope["draft_json"])
    if not set(proposal["requested_permissions"]).issubset(draft["requested_capabilities"]):
        raise PluginSchemaError("$proposal requested permissions exceed the accepted IntentDraft")
    expected_host_evidence = {
        item["digest"]: materialized_evidence_descriptor(item)
        for item in request["evidence"]
    }
    proposal_evidence = {item["digest"]: dict(item) for item in proposal["evidence"]}
    for digest, evidence in expected_host_evidence.items():
        if proposal_evidence.get(digest) != evidence:
            raise PluginSchemaError("$proposal does not preserve invocation materialized evidence")
    expected_accepted = accepted_intent_evidence(
        envelope,
        envelope_digest,
        observed_at_ms=request["proposed_at_ms"],
    )
    if proposal_evidence.get(expected_accepted["digest"]) != expected_accepted:
        raise PluginSchemaError("$proposal does not preserve accepted IntentDraft evidence")


def validate_intent_solver_exchange(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> None:
    """Bind one proposal to the accepted intent, policy, and materialized evidence."""

    envelope = proposal = None
    if request.get("operation") == "propose" and response.get("operation") == "propose":
        try:
            proposal, _canonical = canonical_solver_proposal(response["proposal_json"])
            envelope, _encoded, _envelope_digest = canonical_signed_intent_envelope(
                request["intent_envelope_json"]
            )
        except (KeyError, TypeError, ValueError):
            raise PluginSchemaError(
                "$output proposal or input envelope is unavailable for exchange binding"
            ) from None
    _validate_intent_solver_exchange_documents(
        request,
        response,
        envelope=envelope,
        proposal=proposal,
    )


def intent_solver_protocol_document() -> Dict[str, Any]:
    return {
        "capability": INTENT_SOLVER_CONTRACT.to_dict(),
        "canonicalization": {
            "encoding": "utf-8",
            "floats": "forbidden",
            "integer_range": "-(2^53-1)..(2^53-1)",
            "serialization": "recursive-sorted-keys-compact-json",
        },
        "evidence_schema": deepcopy(_EVIDENCE_SCHEMA),
        "materialized_input_evidence_schema": deepcopy(_MATERIALIZED_EVIDENCE_SCHEMA),
        "input_schema": deepcopy(INTENT_SOLVER_INPUT_SCHEMA),
        "invocation_context_binding": {
            "digest": "sha256-canonical-json",
            "fields": [
                "capability_id",
                "format",
                "idempotency_key",
                "invocation_id",
                "mandate_digest",
                "plugin_id",
                "principal",
                "resource_ids",
            ],
            "provenance": "not-a-signature",
            "source": "host-derived",
        },
        "output_schema": deepcopy(INTENT_SOLVER_OUTPUT_SCHEMA),
        "proposal_schema": deepcopy(SOLVER_PROPOSAL_SCHEMA),
        "semantics": {
            "authority": "none",
            "evidence": "content-addressed-provenance-labelled-claims",
            "execution": "forbidden",
            "input": "signed-envelope-plus-host-acceptance-and-policy-binding",
            "output": "unsigned-unverified-claim-requiring-selection",
            "promotion": "deterministic-policy-decision-and-explicit-selection-required",
            "response_context_binding": "host-invocation-and-authority-exact",
        },
        "wire_limits": {
            "max_document_bytes": INTENT_SOLVER_MAX_DOCUMENT_BYTES,
            "max_evidence": INTENT_SOLVER_MAX_EVIDENCE,
            "max_evidence_item_bytes": INTENT_SOLVER_MAX_EVIDENCE_ITEM_BYTES,
            "max_evidence_total_bytes": INTENT_SOLVER_MAX_EVIDENCE_TOTAL_BYTES,
            "max_items": INTENT_SOLVER_MAX_ITEMS,
            "max_proposal_bytes": INTENT_SOLVER_MAX_PROPOSAL_BYTES,
            "max_safe_integer": INTENT_RESOLVER_MAX_SAFE_INTEGER,
            "max_text_bytes": INTENT_SOLVER_MAX_TEXT_BYTES,
            "max_ttl_ms": INTENT_SOLVER_MAX_TTL_MS,
        },
    }


def intent_solver_protocol_digest() -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(intent_solver_protocol_document())
    ).hexdigest()


__all__ = [
    "GovernedIntentSolverInvocation",
    "INTENT_SOLVER_CAPABILITY_ID",
    "INTENT_SOLVER_CAPABILITY_VERSION",
    "INTENT_SOLVER_CONTRACT",
    "INTENT_SOLVER_CONTEXT_FORMAT",
    "INTENT_SOLVER_INPUT_SCHEMA",
    "INTENT_SOLVER_MAX_DOCUMENT_BYTES",
    "INTENT_SOLVER_MAX_EVIDENCE",
    "INTENT_SOLVER_MAX_EVIDENCE_ITEM_BYTES",
    "INTENT_SOLVER_MAX_EVIDENCE_TOTAL_BYTES",
    "INTENT_SOLVER_MAX_ITEMS",
    "INTENT_SOLVER_MAX_PROPOSAL_BYTES",
    "INTENT_SOLVER_MAX_SAFE_INTEGER",
    "INTENT_SOLVER_MAX_TEXT_BYTES",
    "INTENT_SOLVER_MAX_TTL_MS",
    "INTENT_SOLVER_OUTPUT_SCHEMA",
    "SOLVER_PROPOSAL_FORMAT",
    "SOLVER_PROPOSAL_SCHEMA",
    "IntentSolverPreparationError",
    "accepted_intent_evidence",
    "canonical_signed_intent_envelope",
    "canonical_solver_proposal",
    "intent_solver_invocation_context_digest",
    "intent_solver_protocol_digest",
    "intent_solver_protocol_document",
    "materialized_evidence_descriptor",
    "prepare_governed_intent_solver_invocation",
    "solver_proposal_digest",
    "validate_intent_solver_authority",
    "validate_intent_solver_context_binding",
    "validate_intent_solver_exchange",
    "validate_intent_solver_input",
    "validate_intent_solver_output",
    "validate_solver_proposal",
]
