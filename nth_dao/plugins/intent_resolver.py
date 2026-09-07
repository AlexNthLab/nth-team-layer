"""Language-neutral contract for non-authoritative Intent Draft resolution.

Resolvers may interpret source text and suggest a reviewable draft. They never
sign the draft, grant capabilities, create a mandate, or make it executable.
The Host must bind every result back to the exact request before displaying or
persisting it.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Dict

from nth_dao.canonical_json import canonical_json

from .contracts import CapabilityContract, schema_digest
from .host import InvocationAuthority, PluginAuthorizationError
from .schema import PluginSchemaError, validate_instance


INTENT_RESOLVER_CAPABILITY_ID = "org.nth-dao.intent.resolve"
INTENT_RESOLVER_CAPABILITY_VERSION = "1.0.0"
INTENT_DRAFT_FORMAT = "org.nth-dao.intent-draft"
INTENT_RESOLVER_CONTEXT_FORMAT = "org.nth-dao.intent-resolver-invocation-context.v1"
INTENT_RESOLVER_MAX_DOCUMENT_BYTES = 1_048_576
INTENT_RESOLVER_MAX_SOURCE_BYTES = 32_768
INTENT_RESOLVER_MAX_DRAFT_BYTES = 131_072
INTENT_RESOLVER_MAX_SAFE_INTEGER = 9_007_199_254_740_991
INTENT_RESOLVER_MAX_ATTACHMENTS = 16
INTENT_RESOLVER_MAX_ITEMS = 32

_AUTOMATION_LEVELS = ("A0", "A1", "A2", "A3", "A4")
_SOURCE_KINDS = ("agent", "human", "system")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_LOCALE_RE = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}$")
_MEDIA_TYPE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/"
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$"
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_ATTACHMENT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "media_type": {"type": "string", "minLength": 3, "maxLength": 255},
        "name": {"type": "string", "maxLength": 256},
        "size_bytes": {
            "type": "integer",
            "minimum": 0,
            "maximum": INTENT_RESOLVER_MAX_SAFE_INTEGER,
        },
        "verification_status": {"type": "string", "enum": ["unverified"]},
    },
    "required": [
        "digest",
        "media_type",
        "name",
        "size_bytes",
        "verification_status",
    ],
}

_CLARIFICATION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "code": {"type": "string", "minLength": 1, "maxLength": 128},
        "question": {"type": "string", "minLength": 1, "maxLength": 2_000},
    },
    "required": ["code", "question"],
}

_TEXT_LIST_SCHEMA: Dict[str, Any] = {
    "type": "array",
    "maxItems": INTENT_RESOLVER_MAX_ITEMS,
    "items": {"type": "string", "minLength": 1, "maxLength": 2_000},
}

INTENT_DRAFT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "assumptions": deepcopy(_TEXT_LIST_SCHEMA),
        "attachments": {
            "type": "array",
            "maxItems": INTENT_RESOLVER_MAX_ATTACHMENTS,
            "items": deepcopy(_ATTACHMENT_SCHEMA),
        },
        "authority": {"type": "string", "enum": ["none"]},
        "automation_ceiling": {"type": "string", "enum": list(_AUTOMATION_LEVELS)},
        "clarifications": {
            "type": "array",
            "maxItems": INTENT_RESOLVER_MAX_ITEMS,
            "items": deepcopy(_CLARIFICATION_SCHEMA),
        },
        "commit_authority": {"type": "boolean"},
        "constraints": deepcopy(_TEXT_LIST_SCHEMA),
        "executable": {"type": "boolean"},
        "format": {"type": "string", "enum": [INTENT_DRAFT_FORMAT]},
        "intent_version": {"type": "string", "enum": ["1"]},
        "locale": {"type": "string", "minLength": 2, "maxLength": 35},
        "outcomes": deepcopy(_TEXT_LIST_SCHEMA),
        "request_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "request_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "requested_capabilities": {
            "type": "array",
            "maxItems": INTENT_RESOLVER_MAX_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": 256},
        },
        "review_required": {"type": "boolean"},
        "risks": deepcopy(_TEXT_LIST_SCHEMA),
        "source_kind": {"type": "string", "enum": list(_SOURCE_KINDS)},
        "source_text": {
            "type": "string",
            "minLength": 1,
            "maxLength": INTENT_RESOLVER_MAX_SOURCE_BYTES,
        },
        "summary": {"type": "string", "minLength": 1, "maxLength": 2_000},
    },
    "required": [
        "assumptions",
        "attachments",
        "authority",
        "automation_ceiling",
        "clarifications",
        "commit_authority",
        "constraints",
        "executable",
        "format",
        "intent_version",
        "locale",
        "outcomes",
        "request_digest",
        "request_id",
        "requested_capabilities",
        "review_required",
        "risks",
        "source_kind",
        "source_text",
        "summary",
    ],
}

INTENT_RESOLVER_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "attachments": {
            "type": "array",
            "maxItems": INTENT_RESOLVER_MAX_ATTACHMENTS,
            "items": deepcopy(_ATTACHMENT_SCHEMA),
        },
        "automation_ceiling": {"type": "string", "enum": list(_AUTOMATION_LEVELS)},
        "locale": {"type": "string", "minLength": 2, "maxLength": 35},
        "operation": {"type": "string", "enum": ["probe", "resolve"]},
        "request_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "source_kind": {"type": "string", "enum": list(_SOURCE_KINDS)},
        "source_text": {
            "type": "string",
            "minLength": 1,
            "maxLength": INTENT_RESOLVER_MAX_SOURCE_BYTES,
        },
    },
    "required": ["operation"],
}

INTENT_RESOLVER_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "authority": {"type": "string", "enum": ["none"]},
        "commit_authority": {"type": "boolean"},
        "detail": {"type": "string", "maxLength": 2_048},
        "draft_json": {"type": "string", "maxLength": INTENT_RESOLVER_MAX_DRAFT_BYTES},
        "draft_sha256": {"type": "string", "maxLength": 71},
        "executable": {"type": "boolean"},
        "invocation_context_digest": {
            "type": "string",
            "minLength": 71,
            "maxLength": 71,
        },
        "max_attachments": {
            "type": "integer",
            "minimum": 1,
            "maximum": INTENT_RESOLVER_MAX_SAFE_INTEGER,
        },
        "max_source_bytes": {
            "type": "integer",
            "minimum": 1,
            "maximum": INTENT_RESOLVER_MAX_SAFE_INTEGER,
        },
        "operation": {"type": "string", "enum": ["probe", "resolve"]},
        "ready": {"type": "boolean"},
        "request_digest": {"type": "string", "maxLength": 71},
        "request_id": {"type": "string", "maxLength": 256},
        "resolver_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "status": {"type": "string", "enum": ["", "draft", "needs-clarification"]},
        "supported_automation_levels": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(_AUTOMATION_LEVELS),
            "items": {"type": "string", "enum": list(_AUTOMATION_LEVELS)},
        },
    },
    "required": [
        "authority",
        "commit_authority",
        "detail",
        "draft_json",
        "draft_sha256",
        "executable",
        "invocation_context_digest",
        "max_attachments",
        "max_source_bytes",
        "operation",
        "ready",
        "request_digest",
        "request_id",
        "resolver_id",
        "status",
        "supported_automation_levels",
    ],
}

INTENT_RESOLVER_CONTRACT = CapabilityContract(
    capability_id=INTENT_RESOLVER_CAPABILITY_ID,
    version=INTENT_RESOLVER_CAPABILITY_VERSION,
    input_schema_digest=schema_digest(INTENT_RESOLVER_INPUT_SCHEMA),
    output_schema_digest=schema_digest(INTENT_RESOLVER_OUTPUT_SCHEMA),
    effects=("none",),
    consistency="C0",
    privacy="confidential",
    security="untrusted-hint",
    cardinality="many",
    deterministic=False,
    retention="none",
    failure_semantics="retry-safe",
)


def validate_intent_resolver_input(value: Mapping[str, Any]) -> None:
    """Validate one closed probe or resolve request."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$input must be an object")
    _validate_document_size(value, path="$input")
    validate_instance(value, INTENT_RESOLVER_INPUT_SCHEMA, path="$input")
    operation = value.get("operation")
    if operation == "probe":
        if set(value) != {"operation"}:
            raise PluginSchemaError("$input probe accepts only operation")
        return
    if operation != "resolve":
        raise PluginSchemaError("$input.operation is unsupported")
    required = {
        "attachments",
        "automation_ceiling",
        "locale",
        "operation",
        "request_id",
        "source_kind",
        "source_text",
    }
    if set(value) != required:
        raise PluginSchemaError("$input resolve has missing or unknown fields")
    _validate_identifier(value["request_id"], path="$input.request_id")
    _validate_locale(value["locale"], path="$input.locale")
    _validate_text(
        value["source_text"],
        path="$input.source_text",
        maximum_bytes=INTENT_RESOLVER_MAX_SOURCE_BYTES,
        multiline=True,
    )
    _validate_attachments(value["attachments"], path="$input.attachments")


def intent_resolver_request_digest(value: Mapping[str, Any]) -> str:
    """Return the content address of one validated resolve request."""

    validate_intent_resolver_input(value)
    if value.get("operation") != "resolve":
        raise ValueError("only resolve requests have a request digest")
    return "sha256:" + hashlib.sha256(canonical_json(dict(value))).hexdigest()


def validate_intent_resolver_authority(
    _request: Mapping[str, Any],
    authority: InvocationAuthority,
) -> None:
    """Require narrow local authority for non-authoritative resolution."""

    if not isinstance(authority, InvocationAuthority):
        raise PluginAuthorizationError("intent resolver requires local invocation authority")
    if INTENT_RESOLVER_CAPABILITY_ID not in authority.capability_ids:
        raise PluginAuthorizationError("intent resolver authority lacks capability scope")
    if authority.mandate_digest or authority.idempotency_key or authority.resource_ids:
        raise PluginAuthorizationError(
            "intent resolver must not receive mandate, idempotency, or resource authority"
        )


def intent_resolver_invocation_context_digest(value: Mapping[str, Any]) -> str:
    """Content-address one exact Host invocation context projection."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$context must be an object")
    required = {
        "capability_id",
        "format",
        "invocation_id",
        "plugin_id",
        "principal",
    }
    if set(value) != required:
        raise PluginSchemaError("$context has missing or unknown fields")
    if value["format"] != INTENT_RESOLVER_CONTEXT_FORMAT:
        raise PluginSchemaError("$context.format is invalid")
    _validate_identifier(value["plugin_id"], path="$context.plugin_id")
    _validate_identifier(value["capability_id"], path="$context.capability_id")
    if value["capability_id"] != INTENT_RESOLVER_CAPABILITY_ID:
        raise PluginSchemaError("$context.capability_id is invalid")
    _validate_identifier(value["invocation_id"], path="$context.invocation_id")
    _validate_text(
        value["principal"],
        path="$context.principal",
        maximum_bytes=512,
    )
    return "sha256:" + hashlib.sha256(canonical_json(dict(value))).hexdigest()


def validate_intent_resolver_context_binding(
    response: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    """Reject a response replayed under a different Host invocation context."""

    expected = intent_resolver_invocation_context_digest(context)
    if response.get("invocation_context_digest") != expected:
        raise PluginSchemaError(
            "$output.invocation_context_digest does not bind Host invocation context"
        )


def canonical_intent_draft(value: str) -> tuple[Dict[str, Any], bytes]:
    """Parse and validate one canonical, unsigned Intent Draft document."""

    if not isinstance(value, str):
        raise ValueError("draft_json must be text")
    encoded = value.encode("utf-8")
    if len(encoded) > INTENT_RESOLVER_MAX_DRAFT_BYTES:
        raise ValueError("draft_json exceeds the UTF-8 byte limit")
    try:
        document = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("draft_json must contain valid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("draft_json must contain an object")
    validate_intent_draft(document)
    canonical = canonical_json(document)
    if canonical != encoded:
        raise ValueError("draft_json must use canonical JSON encoding")
    return document, canonical


def intent_draft_digest(value: str) -> str:
    """Return the prefixed SHA-256 content address of a canonical draft."""

    _document, encoded = canonical_intent_draft(value)
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_intent_draft(value: Mapping[str, Any]) -> None:
    """Validate the closed, explicitly non-authoritative draft semantics."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$draft must be an object")
    _validate_document_size(value, path="$draft", maximum=INTENT_RESOLVER_MAX_DRAFT_BYTES)
    validate_instance(value, INTENT_DRAFT_SCHEMA, path="$draft")
    _validate_identifier(value["request_id"], path="$draft.request_id")
    _validate_locale(value["locale"], path="$draft.locale")
    if _SHA256_RE.fullmatch(value["request_digest"]) is None:
        raise PluginSchemaError("$draft.request_digest is invalid")
    if (
        value["authority"] != "none"
        or value["commit_authority"] is not False
        or value["executable"] is not False
        or value["review_required"] is not True
    ):
        raise PluginSchemaError("$draft must remain review-only and non-authoritative")
    _validate_text(
        value["source_text"],
        path="$draft.source_text",
        maximum_bytes=INTENT_RESOLVER_MAX_SOURCE_BYTES,
        multiline=True,
    )
    _validate_text(value["summary"], path="$draft.summary", multiline=True)
    _validate_attachments(value["attachments"], path="$draft.attachments")
    _validate_text_list(value["outcomes"], path="$draft.outcomes")
    _validate_text_list(value["assumptions"], path="$draft.assumptions")
    _validate_text_list(value["constraints"], path="$draft.constraints")
    _validate_text_list(value["risks"], path="$draft.risks")
    capabilities = value["requested_capabilities"]
    if capabilities != sorted(set(capabilities)):
        raise PluginSchemaError("$draft.requested_capabilities must be sorted and unique")
    for index, capability in enumerate(capabilities):
        _validate_identifier(
            capability,
            path=f"$draft.requested_capabilities[{index}]",
        )
    clarification_codes: list[str] = []
    for index, clarification in enumerate(value["clarifications"]):
        _validate_identifier(
            clarification["code"],
            path=f"$draft.clarifications[{index}].code",
        )
        _validate_text(
            clarification["question"],
            path=f"$draft.clarifications[{index}].question",
            multiline=True,
        )
        clarification_codes.append(clarification["code"])
    if len(clarification_codes) != len(set(clarification_codes)):
        raise PluginSchemaError("$draft clarification codes must be unique")


def validate_intent_resolver_output(value: Mapping[str, Any]) -> None:
    """Validate one provider response and its draft content address."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$output must be an object")
    _validate_document_size(value, path="$output")
    validate_instance(value, INTENT_RESOLVER_OUTPUT_SCHEMA, path="$output")
    _validate_identifier(value["resolver_id"], path="$output.resolver_id")
    if value["supported_automation_levels"] != list(_AUTOMATION_LEVELS):
        raise PluginSchemaError("$output automation levels are incomplete or unordered")
    if value["max_source_bytes"] > INTENT_RESOLVER_MAX_SOURCE_BYTES:
        raise PluginSchemaError("$output max_source_bytes exceeds the wire limit")
    if value["max_attachments"] > INTENT_RESOLVER_MAX_ATTACHMENTS:
        raise PluginSchemaError("$output max_attachments exceeds the wire limit")
    if not value["ready"] or value["detail"]:
        raise PluginSchemaError("$output reference operation must be ready without detail")
    if (
        value["authority"] != "none"
        or value["commit_authority"] is not False
        or value["executable"] is not False
    ):
        raise PluginSchemaError("$output cannot grant authority or execution")
    if _SHA256_RE.fullmatch(value["invocation_context_digest"]) is None:
        raise PluginSchemaError("$output.invocation_context_digest is invalid")
    if value["operation"] == "probe":
        if any(
            value[field]
            for field in (
                "draft_json",
                "draft_sha256",
                "request_digest",
                "request_id",
                "status",
            )
        ):
            raise PluginSchemaError("$output probe cannot carry draft state")
        return
    if value["operation"] != "resolve":
        raise PluginSchemaError("$output.operation is unsupported")
    try:
        draft, encoded = canonical_intent_draft(value["draft_json"])
    except ValueError as exc:
        raise PluginSchemaError(f"$output.draft_json {exc}") from exc
    expected_draft_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    if expected_draft_digest != value["draft_sha256"]:
        raise PluginSchemaError("$output.draft_sha256 does not bind draft_json")
    if value["request_id"] != draft["request_id"]:
        raise PluginSchemaError("$output.request_id does not bind draft_json")
    if value["request_digest"] != draft["request_digest"]:
        raise PluginSchemaError("$output.request_digest does not bind draft_json")
    expected_status = (
        "needs-clarification" if draft["clarifications"] else "draft"
    )
    if value["status"] != expected_status:
        raise PluginSchemaError("$output.status does not match draft clarifications")


def validate_intent_resolver_exchange(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> None:
    """Bind one validated resolver response to its exact validated request."""

    if response.get("operation") != request.get("operation"):
        raise PluginSchemaError("$output.operation does not match $input.operation")
    if request.get("operation") == "probe":
        return
    expected_digest = intent_resolver_request_digest(request)
    if response.get("request_id") != request.get("request_id"):
        raise PluginSchemaError("$output.request_id does not match $input.request_id")
    if response.get("request_digest") != expected_digest:
        raise PluginSchemaError("$output.request_digest does not bind $input")
    try:
        draft, _encoded = canonical_intent_draft(response["draft_json"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PluginSchemaError("$output draft is unavailable for exchange binding") from exc
    for field in (
        "attachments",
        "automation_ceiling",
        "locale",
        "request_id",
        "source_kind",
        "source_text",
    ):
        if draft[field] != request[field]:
            raise PluginSchemaError(f"$draft.{field} does not bind $input.{field}")


def intent_resolver_protocol_document() -> Dict[str, Any]:
    """Return the complete portable resolver protocol document."""

    return {
        "capability": INTENT_RESOLVER_CONTRACT.to_dict(),
        "canonicalization": {
            "encoding": "utf-8",
            "floats": "forbidden",
            "integer_range": "-(2^53-1)..(2^53-1)",
            "serialization": "recursive-sorted-keys-compact-json",
        },
        "draft_schema": deepcopy(INTENT_DRAFT_SCHEMA),
        "error_model": {},
        "input_schema": deepcopy(INTENT_RESOLVER_INPUT_SCHEMA),
        "invocation_authority": {
            "business_scope": "mandate-idempotency-and-resources-forbidden",
            "capability_scope": INTENT_RESOLVER_CAPABILITY_ID,
            "principal": "host-selected-local-attribution",
        },
        "invocation_context_binding": {
            "digest": "sha256-canonical-json",
            "fields": [
                "capability_id",
                "format",
                "invocation_id",
                "plugin_id",
                "principal",
            ],
            "format": INTENT_RESOLVER_CONTEXT_FORMAT,
            "provenance": "not-a-signature",
            "source": "host-derived",
        },
        "output_schema": deepcopy(INTENT_RESOLVER_OUTPUT_SCHEMA),
        "semantics": {
            "authority": "none",
            "execution": "forbidden",
            "input_binding": "request-and-source-fields-exact",
            "output": "unsigned-review-required-claim",
            "promotion": "new-signed-intent-envelope-required",
            "response_context_binding": "host-invocation-exact",
        },
        "wire_limits": {
            "max_attachments": INTENT_RESOLVER_MAX_ATTACHMENTS,
            "max_document_bytes": INTENT_RESOLVER_MAX_DOCUMENT_BYTES,
            "max_draft_bytes": INTENT_RESOLVER_MAX_DRAFT_BYTES,
            "max_items": INTENT_RESOLVER_MAX_ITEMS,
            "max_safe_integer": INTENT_RESOLVER_MAX_SAFE_INTEGER,
            "max_source_bytes": INTENT_RESOLVER_MAX_SOURCE_BYTES,
        },
    }


def intent_resolver_protocol_digest() -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(intent_resolver_protocol_document())
    ).hexdigest()


def intent_resolver_wire_vectors() -> Dict[str, Any]:
    """Return positive and negative vectors for other language implementations."""

    request = {
        "attachments": [
            {
                "digest": "sha256:" + ("a" * 64),
                "media_type": "text/plain",
                "name": "caf\u00e9-requirements.txt",
                "size_bytes": 128,
                "verification_status": "unverified",
            }
        ],
        "automation_ceiling": "A1",
        "locale": "en",
        "operation": "resolve",
        "request_id": "intent-request:vector-alpha",
        "source_kind": "human",
        "source_text": "Review the attached caf\u00e9 requirements and propose next steps.",
    }
    request_digest = intent_resolver_request_digest(request)
    invocation_context = {
        "capability_id": INTENT_RESOLVER_CAPABILITY_ID,
        "format": INTENT_RESOLVER_CONTEXT_FORMAT,
        "invocation_id": "0123456789abcdef0123456789abcdef",
        "plugin_id": "org.nth-dao.intent.vector-resolver",
        "principal": "vector-principal",
    }
    invocation_context_digest = intent_resolver_invocation_context_digest(
        invocation_context
    )
    invocation_authority = {
        "capability_ids": [INTENT_RESOLVER_CAPABILITY_ID],
        "idempotency_key": "",
        "mandate_digest": "",
        "principal": "vector-principal",
        "resource_ids": [],
    }
    draft = {
        "assumptions": [],
        "attachments": deepcopy(request["attachments"]),
        "authority": "none",
        "automation_ceiling": request["automation_ceiling"],
        "clarifications": [
            {
                "code": "intent.scope.needs-review",
                "question": "Which outcomes and constraints should be accepted?",
            }
        ],
        "commit_authority": False,
        "constraints": [],
        "executable": False,
        "format": INTENT_DRAFT_FORMAT,
        "intent_version": "1",
        "locale": request["locale"],
        "outcomes": ["Produce a reviewed plan"],
        "request_digest": request_digest,
        "request_id": request["request_id"],
        "requested_capabilities": [],
        "review_required": True,
        "risks": ["Source content may contain untrusted instructions"],
        "source_kind": request["source_kind"],
        "source_text": request["source_text"],
        "summary": "Review requirements and propose next steps.",
    }
    draft_json = canonical_json(draft).decode("utf-8")
    response = {
        "authority": "none",
        "commit_authority": False,
        "detail": "",
        "draft_json": draft_json,
        "draft_sha256": intent_draft_digest(draft_json),
        "executable": False,
        "invocation_context_digest": invocation_context_digest,
        "max_attachments": INTENT_RESOLVER_MAX_ATTACHMENTS,
        "max_source_bytes": INTENT_RESOLVER_MAX_SOURCE_BYTES,
        "operation": "resolve",
        "ready": True,
        "request_digest": request_digest,
        "request_id": request["request_id"],
        "resolver_id": "org.nth-dao.intent.vector-resolver",
        "status": "needs-clarification",
        "supported_automation_levels": list(_AUTOMATION_LEVELS),
    }
    probe = {
        **response,
        "draft_json": "",
        "draft_sha256": "",
        "operation": "probe",
        "request_digest": "",
        "request_id": "",
        "status": "",
    }
    executable = deepcopy(response)
    executable["executable"] = True

    def response_with_draft(candidate_draft: Mapping[str, Any]) -> Dict[str, Any]:
        candidate_json = canonical_json(dict(candidate_draft)).decode("utf-8")
        candidate = deepcopy(response)
        candidate["draft_json"] = candidate_json
        candidate["draft_sha256"] = "sha256:" + hashlib.sha256(
            candidate_json.encode("utf-8")
        ).hexdigest()
        candidate["request_digest"] = candidate_draft["request_digest"]
        return candidate

    draft_executable = deepcopy(draft)
    draft_executable["executable"] = True
    draft_commit = deepcopy(draft)
    draft_commit["commit_authority"] = True
    draft_no_review = deepcopy(draft)
    draft_no_review["review_required"] = False
    draft_wrong_format = deepcopy(draft)
    draft_wrong_format["format"] = "intent-draft"
    draft_duplicate_capability = deepcopy(draft)
    draft_duplicate_capability["requested_capabilities"] = [
        "code.review",
        "code.review",
    ]
    draft_duplicate_attachment = deepcopy(draft)
    draft_duplicate_attachment["attachments"] = [
        deepcopy(draft["attachments"][0]),
        deepcopy(draft["attachments"][0]),
    ]
    draft_verified_attachment = deepcopy(draft)
    draft_verified_attachment["attachments"][0]["verification_status"] = "verified"
    wrong_draft_digest = deepcopy(response)
    wrong_draft_digest["draft_sha256"] = "sha256:" + ("0" * 64)
    wrong_response_request_digest = deepcopy(response)
    wrong_response_request_digest["request_digest"] = "sha256:" + ("1" * 64)
    rewritten_source = deepcopy(response)
    rewritten_draft = deepcopy(draft)
    rewritten_draft["source_text"] = "Different source text"
    rewritten_source["draft_json"] = canonical_json(rewritten_draft).decode("utf-8")
    rewritten_source["draft_sha256"] = intent_draft_digest(
        rewritten_source["draft_json"]
    )
    rebound_digest_draft = deepcopy(draft)
    rebound_digest_draft["request_digest"] = "sha256:" + ("2" * 64)
    rebound_digest = response_with_draft(rebound_digest_draft)
    replayed_context = deepcopy(invocation_context)
    replayed_context["principal"] = "different-principal"
    boolean_size_request = deepcopy(request)
    boolean_size_request["attachments"][0]["size_bytes"] = True
    wrong_capability_authority = {
        **invocation_authority,
        "capability_ids": ["org.example.other"],
    }
    mandate_authority = {
        **invocation_authority,
        "mandate_digest": "sha256:" + ("3" * 64),
    }
    idempotency_authority = {
        **invocation_authority,
        "idempotency_key": "intent-request:smuggled",
    }
    resource_authority = {
        **invocation_authority,
        "resource_ids": ["sha256:" + ("4" * 64)],
    }
    vectors = {
        "negative_authorities": [
            {
                "authority": wrong_capability_authority,
                "expected_error_contains": "lacks capability scope",
                "name": "resolver-authority-requires-capability",
                "request": request,
            },
            {
                "authority": mandate_authority,
                "expected_error_contains": "must not receive",
                "name": "resolver-authority-rejects-mandate",
                "request": request,
            },
            {
                "authority": idempotency_authority,
                "expected_error_contains": "must not receive",
                "name": "resolver-authority-rejects-idempotency",
                "request": request,
            },
            {
                "authority": resource_authority,
                "expected_error_contains": "must not receive",
                "name": "resolver-authority-rejects-resources",
                "request": request,
            },
        ],
        "negative_context_bindings": [
            {
                "context": replayed_context,
                "expected_error_contains": "does not bind Host invocation context",
                "name": "response-cannot-cross-principal-context",
                "response": response,
            }
        ],
        "negative_exchanges": [
            {
                "expected_error_contains": "source_text",
                "name": "draft-cannot-rewrite-source",
                "request": request,
                "response": rewritten_source,
            },
            {
                "expected_error_contains": "request_digest",
                "name": "draft-cannot-rebind-request-digest",
                "request": request,
                "response": rebound_digest,
            },
        ],
        "negative_inputs": [
            {
                "expected_error_contains": "UTF-8 byte limit",
                "input": {
                    **deepcopy(request),
                    "source_text": "\u754c"
                    * ((INTENT_RESOLVER_MAX_SOURCE_BYTES // 3) + 1),
                },
                "name": "source-byte-limit-is-not-character-limit",
            },
            {
                "expected_error_contains": "must be integer",
                "input": boolean_size_request,
                "name": "attachment-size-cannot-be-boolean",
            },
            {
                "expected_error_contains": "unknown fields",
                "input": {**deepcopy(request), "mandate_id": "forbidden"},
                "name": "resolve-cannot-smuggle-mandate-field",
            },
        ],
        "negative_outputs": [
            {
                "expected_error_contains": "cannot grant authority or execution",
                "name": "resolver-cannot-make-draft-executable",
                "output": executable,
            },
            {
                "expected_error_contains": "review-only",
                "name": "draft-cannot-be-executable",
                "output": response_with_draft(draft_executable),
            },
            {
                "expected_error_contains": "review-only",
                "name": "draft-cannot-grant-commit-authority",
                "output": response_with_draft(draft_commit),
            },
            {
                "expected_error_contains": "review-only",
                "name": "draft-cannot-skip-review",
                "output": response_with_draft(draft_no_review),
            },
            {
                "expected_error_contains": "format",
                "name": "draft-format-is-closed",
                "output": response_with_draft(draft_wrong_format),
            },
            {
                "expected_error_contains": "sorted and unique",
                "name": "draft-capabilities-cannot-be-duplicated",
                "output": response_with_draft(draft_duplicate_capability),
            },
            {
                "expected_error_contains": "digests must be unique",
                "name": "draft-attachments-cannot-be-duplicated",
                "output": response_with_draft(draft_duplicate_attachment),
            },
            {
                "expected_error_contains": "verification_status",
                "name": "draft-attachment-verification-cannot-be-invented",
                "output": response_with_draft(draft_verified_attachment),
            },
            {
                "expected_error_contains": "does not bind",
                "name": "draft-content-digest-must-match",
                "output": wrong_draft_digest,
            },
            {
                "expected_error_contains": "does not bind draft_json",
                "name": "response-request-digest-must-match-draft",
                "output": wrong_response_request_digest,
            },
        ],
        "positive_exchanges": [
            {
                "authority": invocation_authority,
                "context": invocation_context,
                "request": {"operation": "probe"},
                "response": probe,
            },
            {
                "authority": invocation_authority,
                "context": invocation_context,
                "request": request,
                "response": response,
            },
        ],
        "positive_inputs": [{"operation": "probe"}, request],
        "positive_outputs": [probe, response],
        "protocol_digest": intent_resolver_protocol_digest(),
    }
    vectors["negative_inputs"].extend(
        [
            {
                "name": "probe-cannot-carry-source",
                "input": {"operation": "probe", "source_text": "unexpected"},
                "expected_error_contains": "probe accepts only operation",
            },
            {
                "name": "resolve-requires-source-fields",
                "input": {"operation": "resolve"},
                "expected_error_contains": "resolve has missing or unknown fields",
            },
        ]
    )
    for name, field, value, error in (
        ("blank-source", "source_text", "   ", "must be non-empty text"),
        ("unicode-blank-source", "source_text", "\u0085", "must be non-empty text"),
        ("control-source", "source_text", "a\x00b", "unsupported control characters"),
        ("invalid-locale", "locale", "en_US", "locale is invalid"),
        ("invalid-request-id", "request_id", "has spaces", "request_id is invalid"),
    ):
        vectors["negative_inputs"].append(
            {
                "name": name,
                "input": {**deepcopy(request), field: value},
                "expected_error_contains": error,
            }
        )
    for field, value, error in (
        ("digest", "sha256:" + "g" * 64, "digest is invalid"),
        ("media_type", "text/plain; charset=utf-8", "media_type is invalid"),
        ("name", "bad\x00name", "unsupported control characters"),
        ("size_bytes", -1, "below the minimum"),
        ("size_bytes", INTENT_RESOLVER_MAX_SAFE_INTEGER + 1, "exceeds the maximum"),
    ):
        candidate = deepcopy(request)
        candidate["attachments"][0][field] = value
        vectors["negative_inputs"].append(
            {
                "name": f"invalid-attachment-{field}-{len(vectors['negative_inputs'])}",
                "input": candidate,
                "expected_error_contains": error,
            }
        )
    sixteen_attachments = [
        {**deepcopy(request["attachments"][0]), "digest": f"sha256:{index:064x}"}
        for index in range(INTENT_RESOLVER_MAX_ATTACHMENTS)
    ]
    vectors["positive_inputs"].extend(
        [
            {**deepcopy(request), "source_text": "\ufeff"},
            {**deepcopy(request), "attachments": sixteen_attachments},
        ]
    )
    vectors["negative_inputs"].extend(
        [
            {
                "name": "attachment-limit-seventeen",
                "input": {**deepcopy(request), "attachments": sixteen_attachments + request["attachments"]},
                "expected_error_contains": "too many items",
            },
            {
                "name": "duplicate-input-attachment",
                "input": {**deepcopy(request), "attachments": request["attachments"] * 2},
                "expected_error_contains": "digests must be unique",
            },
        ]
    )
    for field, value, error in (
        ("request_id", "different-id", "request_id does not bind draft_json"),
        ("status", "draft", "status does not match draft clarifications"),
        ("operation", "probe", "probe cannot carry draft state"),
        ("ready", False, "must be ready without detail"),
        ("detail", "hidden error", "must be ready without detail"),
        ("max_source_bytes", INTENT_RESOLVER_MAX_SOURCE_BYTES + 1, "exceeds the wire limit"),
        ("max_attachments", INTENT_RESOLVER_MAX_ATTACHMENTS + 1, "exceeds the wire limit"),
        ("supported_automation_levels", list(reversed(_AUTOMATION_LEVELS)), "incomplete or unordered"),
        ("invocation_context_digest", "sha256:" + "g" * 64, "invocation_context_digest is invalid"),
        ("resolver_id", "invalid resolver", "resolver_id is invalid"),
    ):
        vectors["negative_outputs"].append(
            {
                "name": f"invalid-response-{field}",
                "output": {**deepcopy(response), field: value},
                "expected_error_contains": error,
            }
        )
    for field, value, error in (
        ("summary", "  ", "must be non-empty text"),
        ("risks", ["\x00"], "unsupported control characters"),
        ("requested_capabilities", ["invalid capability"], "requested_capabilities"),
        ("clarifications", draft["clarifications"] * 2, "clarification codes must be unique"),
    ):
        vectors["negative_outputs"].append(
            {
                "name": f"invalid-draft-{field}",
                "output": response_with_draft({**deepcopy(draft), field: value}),
                "expected_error_contains": error,
            }
        )
    for field, value, error in (
        ("format", "wrong-format", "context.format is invalid"),
        ("capability_id", "org.example.other", "context.capability_id is invalid"),
        ("principal", " ", "must be non-empty text"),
        ("principal", "x" * 513, "UTF-8 byte limit"),
    ):
        candidate_context = {**invocation_context, field: value}
        vectors["negative_context_bindings"].append(
            {
                "name": f"invalid-context-{field}-{len(vectors['negative_context_bindings'])}",
                "context": candidate_context,
                "response": {
                    **response,
                    "invocation_context_digest": "sha256:" + hashlib.sha256(
                        canonical_json(candidate_context)
                    ).hexdigest(),
                },
                "expected_error_contains": error,
            }
        )
    unused_property_keyword = deepcopy(INTENT_RESOLVER_INPUT_SCHEMA)
    unused_property_keyword["properties"]["source_text"]["pattern"] = "unsupported"
    unused_item_keyword = deepcopy(INTENT_DRAFT_SCHEMA)
    unused_item_keyword["properties"]["assumptions"]["items"]["pattern"] = "unsupported"
    unknown_required = deepcopy(INTENT_RESOLVER_INPUT_SCHEMA)
    unknown_required["required"].append("undeclared")
    vectors["negative_schemas"] = [
        {
            "name": name,
            "schema": schema,
            "expected_error_contains": error,
        }
        for name, schema, error in (
            ("optional-field-unknown-keyword", unused_property_keyword, "unsupported keyword"),
            ("empty-array-child-unknown-keyword", unused_item_keyword, "unsupported keyword"),
            ("required-must-be-declared", unknown_required, "reference declared properties"),
        )
    ]
    return vectors


def intent_resolver_vector_documents() -> Dict[str, Dict[str, Any]]:
    protocol = intent_resolver_protocol_document()
    return {
        "intent-resolver-capability-v1.json": {
            "capability": INTENT_RESOLVER_CONTRACT.to_dict(),
            "draft_schema": "intent-draft-schema-v1.json",
            "expected_protocol_digest": intent_resolver_protocol_digest(),
            "format": "nth-dao-plugin-capability-conformance-v1",
            "input_schema": "intent-resolver-input-schema-v1.json",
            "operation_vectors": "intent-resolver-wire-cases-v1.json",
            "output_schema": "intent-resolver-output-schema-v1.json",
            "schema_version": 1,
        },
        "intent-draft-schema-v1.json": protocol["draft_schema"],
        "intent-resolver-input-schema-v1.json": protocol["input_schema"],
        "intent-resolver-output-schema-v1.json": protocol["output_schema"],
        "intent-resolver-wire-cases-v1.json": intent_resolver_wire_vectors(),
    }


def _validate_identifier(value: Any, *, path: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise PluginSchemaError(f"{path} is invalid")


def _validate_locale(value: Any, *, path: str) -> None:
    if not isinstance(value, str) or _LOCALE_RE.fullmatch(value) is None:
        raise PluginSchemaError(f"{path} is invalid")


def _validate_attachments(value: Any, *, path: str) -> None:
    digests: list[str] = []
    for index, item in enumerate(value):
        if _SHA256_RE.fullmatch(item["digest"]) is None:
            raise PluginSchemaError(f"{path}[{index}].digest is invalid")
        if _MEDIA_TYPE_RE.fullmatch(item["media_type"]) is None:
            raise PluginSchemaError(f"{path}[{index}].media_type is invalid")
        _validate_text(item["name"], path=f"{path}[{index}].name", allow_empty=True)
        digests.append(item["digest"])
    if len(digests) != len(set(digests)):
        raise PluginSchemaError(f"{path} digests must be unique")


def _validate_text_list(value: Any, *, path: str) -> None:
    for index, item in enumerate(value):
        _validate_text(item, path=f"{path}[{index}]", multiline=True)


def _validate_text(
    value: Any,
    *,
    path: str,
    maximum_bytes: int = 8_192,
    multiline: bool = False,
    allow_empty: bool = False,
) -> None:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise PluginSchemaError(f"{path} must be non-empty text")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise PluginSchemaError(f"{path} exceeds the UTF-8 byte limit")
    allowed = {0x09, 0x0A, 0x0D} if multiline else set()
    if any(
        (ord(char) < 0x20 and ord(char) not in allowed) or ord(char) == 0x7F
        for char in value
    ):
        raise PluginSchemaError(f"{path} contains unsupported control characters")


def _validate_document_size(
    value: Mapping[str, Any],
    *,
    path: str,
    maximum: int = INTENT_RESOLVER_MAX_DOCUMENT_BYTES,
) -> None:
    try:
        encoded = canonical_json(dict(value))
    except (RecursionError, TypeError, ValueError) as exc:
        raise PluginSchemaError(f"{path} must be finite canonical JSON") from exc
    if len(encoded) > maximum:
        raise PluginSchemaError(f"{path} exceeds {maximum} canonical UTF-8 bytes")


__all__ = [
    "INTENT_DRAFT_SCHEMA",
    "INTENT_DRAFT_FORMAT",
    "INTENT_RESOLVER_CAPABILITY_ID",
    "INTENT_RESOLVER_CAPABILITY_VERSION",
    "INTENT_RESOLVER_CONTEXT_FORMAT",
    "INTENT_RESOLVER_CONTRACT",
    "INTENT_RESOLVER_INPUT_SCHEMA",
    "INTENT_RESOLVER_MAX_ATTACHMENTS",
    "INTENT_RESOLVER_MAX_DOCUMENT_BYTES",
    "INTENT_RESOLVER_MAX_DRAFT_BYTES",
    "INTENT_RESOLVER_MAX_SAFE_INTEGER",
    "INTENT_RESOLVER_MAX_SOURCE_BYTES",
    "INTENT_RESOLVER_OUTPUT_SCHEMA",
    "canonical_intent_draft",
    "intent_draft_digest",
    "intent_resolver_protocol_digest",
    "intent_resolver_protocol_document",
    "intent_resolver_invocation_context_digest",
    "intent_resolver_request_digest",
    "intent_resolver_vector_documents",
    "intent_resolver_wire_vectors",
    "validate_intent_draft",
    "validate_intent_resolver_authority",
    "validate_intent_resolver_exchange",
    "validate_intent_resolver_context_binding",
    "validate_intent_resolver_input",
    "validate_intent_resolver_output",
]
