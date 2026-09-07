"""Conformance and negative tests for the non-authoritative Intent resolver."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

import nth_dao.plugins as plugin_facade
from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.host import InvocationAuthority, PluginAuthorizationError
from nth_dao.plugins.intent_resolver import (
    INTENT_DRAFT_FORMAT,
    INTENT_RESOLVER_CAPABILITY_ID,
    INTENT_RESOLVER_CONTRACT,
    INTENT_RESOLVER_MAX_ATTACHMENTS,
    INTENT_RESOLVER_MAX_DRAFT_BYTES,
    INTENT_RESOLVER_MAX_SOURCE_BYTES,
    canonical_intent_draft,
    intent_draft_digest,
    intent_resolver_invocation_context_digest,
    intent_resolver_protocol_document,
    intent_resolver_request_digest,
    intent_resolver_vector_documents,
    intent_resolver_wire_vectors,
    validate_intent_draft,
    validate_intent_resolver_authority,
    validate_intent_resolver_exchange,
    validate_intent_resolver_context_binding,
    validate_intent_resolver_input,
    validate_intent_resolver_output,
)
from nth_dao.plugins.schema import PluginSchemaError, validate_schema


VECTOR_DIR = Path(__file__).parents[1] / "nth_dao" / "plugins" / "vectors"


def _vectors():
    return intent_resolver_wire_vectors()


def _resolve_exchange():
    return _vectors()["positive_exchanges"][1]


def _authority(document: dict) -> InvocationAuthority:
    return InvocationAuthority(
        principal=document["principal"],
        capability_ids=frozenset(document["capability_ids"]),
        mandate_digest=document["mandate_digest"],
        idempotency_key=document["idempotency_key"],
        resource_ids=frozenset(document["resource_ids"]),
    )


def test_intent_resolver_contract_is_confidential_and_non_authoritative() -> None:
    assert INTENT_RESOLVER_CAPABILITY_ID == "org.nth-dao.intent.resolve"
    assert INTENT_RESOLVER_CONTRACT.effects == ("none",)
    assert INTENT_RESOLVER_CONTRACT.consistency == "C0"
    assert INTENT_RESOLVER_CONTRACT.privacy == "confidential"
    assert INTENT_RESOLVER_CONTRACT.security == "untrusted-hint"
    assert INTENT_RESOLVER_CONTRACT.retention == "none"
    assert plugin_facade.INTENT_RESOLVER_CONTRACT is INTENT_RESOLVER_CONTRACT
    protocol = intent_resolver_protocol_document()
    assert protocol["error_model"] == {}
    assert protocol["invocation_authority"] == {
        "business_scope": "mandate-idempotency-and-resources-forbidden",
        "capability_scope": INTENT_RESOLVER_CAPABILITY_ID,
        "principal": "host-selected-local-attribution",
    }
    assert protocol["semantics"] == {
        "authority": "none",
        "execution": "forbidden",
        "input_binding": "request-and-source-fields-exact",
        "output": "unsigned-review-required-claim",
        "promotion": "new-signed-intent-envelope-required",
        "response_context_binding": "host-invocation-exact",
    }


def test_intent_resolver_vectors_validate_positive_and_negative_cases() -> None:
    vectors = _vectors()
    for request in vectors["positive_inputs"]:
        validate_intent_resolver_input(request)
    for response in vectors["positive_outputs"]:
        validate_intent_resolver_output(response)
    for exchange in vectors["positive_exchanges"]:
        validate_intent_resolver_authority(
            exchange["request"],
            _authority(exchange["authority"]),
        )
        validate_intent_resolver_exchange(
            exchange["request"],
            exchange["response"],
        )
        validate_intent_resolver_context_binding(
            exchange["response"],
            exchange["context"],
        )
    for case in vectors["negative_authorities"]:
        with pytest.raises(
            PluginAuthorizationError,
            match=case["expected_error_contains"],
        ):
            validate_intent_resolver_authority(
                case["request"],
                _authority(case["authority"]),
            )
    for case in vectors["negative_outputs"]:
        with pytest.raises(
            PluginSchemaError,
            match=case["expected_error_contains"],
        ):
            validate_intent_resolver_output(case["output"])
    for case in vectors["negative_inputs"]:
        with pytest.raises(
            PluginSchemaError,
            match=case["expected_error_contains"],
        ):
            validate_intent_resolver_input(case["input"])
    for case in vectors["negative_exchanges"]:
        validate_intent_resolver_output(case["response"])
        with pytest.raises(
            PluginSchemaError,
            match=case["expected_error_contains"],
        ):
            validate_intent_resolver_exchange(case["request"], case["response"])
    for case in vectors["negative_context_bindings"]:
        validate_intent_resolver_output(case["response"])
        with pytest.raises(
            PluginSchemaError,
            match=case["expected_error_contains"],
        ):
            validate_intent_resolver_context_binding(
                case["response"],
                case["context"],
            )
    for case in vectors["negative_schemas"]:
        with pytest.raises(PluginSchemaError, match=case["expected_error_contains"]):
            validate_schema(case["schema"])


def test_intent_resolver_checked_in_vectors_match_reference_implementation() -> None:
    generated = intent_resolver_vector_documents()

    assert generated
    for filename, expected in generated.items():
        stored = json.loads((VECTOR_DIR / filename).read_text(encoding="utf-8"))
        assert stored == expected


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_intent_resolver_exchange_vectors_verify_independently_in_node() -> None:
    script = r"""
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const vector = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const schemaDir = path.dirname(process.argv[1]);
function loadSchema(name) {
  return JSON.parse(fs.readFileSync(path.join(schemaDir, name), "utf8"));
}
const inputSchema = loadSchema("intent-resolver-input-schema-v1.json");
const outputSchema = loadSchema("intent-resolver-output-schema-v1.json");
const draftSchema = loadSchema("intent-draft-schema-v1.json");
class ValidationError extends Error {}
function fail(message) { throw new ValidationError(message); }
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    const out = Object.create(null);
    for (const key of Object.keys(value).sort()) out[key] = canonical(value[key]);
    return out;
  }
  if (typeof value === "number" && !Number.isSafeInteger(value)) fail("finite canonical JSON");
  if (typeof value === "string") {
    for (const char of value) {
      const point = char.codePointAt(0);
      if (point >= 0xd800 && point <= 0xdfff) fail("finite canonical JSON");
    }
  }
  return value;
}
function canonicalText(value) { return JSON.stringify(canonical(value)); }
function digest(text) {
  return "sha256:" + crypto.createHash("sha256").update(text, "utf8").digest("hex");
}
function validateDefinition(schema, depth = 0) {
  const keywords = {
    object: ["type", "enum", "properties", "required", "additionalProperties"],
    array: ["type", "enum", "items", "minItems", "maxItems"],
    string: ["type", "enum", "minLength", "maxLength"],
    integer: ["type", "enum", "minimum", "maximum"],
    boolean: ["type", "enum"],
  };
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) fail("schema must be object");
  if (depth > 32) fail("schema nesting limit");
  if (!Object.hasOwn(keywords, schema.type)) fail(`unsupported schema type: ${schema.type}`);
  for (const key of Object.keys(schema)) {
    if (!keywords[schema.type].includes(key)) fail(`unsupported schema keyword: ${key}`);
  }
  if (schema.enum !== undefined) {
    if (!Array.isArray(schema.enum) || !schema.enum.length || schema.enum.length > 256) fail("invalid enum");
    for (const item of schema.enum) {
      const matches = schema.type === "integer" ? Number.isSafeInteger(item)
        : ["string", "boolean"].includes(schema.type) && typeof item === schema.type;
      if (!matches) fail("enum values must be scalar values matching the schema type");
    }
  }
  if (schema.type === "object") {
    const properties = schema.properties === undefined ? {} : schema.properties;
    if (properties === null || typeof properties !== "object" || Array.isArray(properties)) fail("invalid properties");
    if (schema.additionalProperties !== false) fail("additionalProperties must be explicitly false");
    if (Object.keys(properties).length > 256) fail("too many schema fields");
    const required = schema.required === undefined ? [] : schema.required;
    if (!Array.isArray(required) || new Set(required).size !== required.length
        || required.some((key) => typeof key !== "string" || !Object.hasOwn(properties, key))) {
      fail("required must be unique and reference declared properties");
    }
    for (const [key, child] of Object.entries(properties)) {
      if (!key || Buffer.byteLength(key, "utf8") > 128) fail("invalid field name");
      validateDefinition(child, depth + 1);
    }
  } else if (schema.type === "array") {
    if (!Object.hasOwn(schema, "items")) fail("items is required");
    validateDefinition(schema.items, depth + 1);
  }
  for (const [low, high] of [["minLength", "maxLength"], ["minItems", "maxItems"], ["minimum", "maximum"]]) {
    for (const key of [low, high]) {
      if (schema[key] !== undefined && (!Number.isSafeInteger(schema[key])
          || (key !== "minimum" && key !== "maximum" && schema[key] < 0))) fail("invalid schema bound");
    }
    if (schema[low] !== undefined && schema[high] !== undefined && schema[low] > schema[high]) fail("inverted size range");
  }
}
for (const schema of [inputSchema, outputSchema, draftSchema]) validateDefinition(schema);
function validateSchema(value, schema, where) {
  const matches = schema.type === "object"
    ? value !== null && typeof value === "object" && !Array.isArray(value)
    : schema.type === "array" ? Array.isArray(value)
    : schema.type === "integer" ? Number.isSafeInteger(value)
    : typeof value === schema.type;
  if (!matches) fail(`${where} must be ${schema.type}`);
  if (schema.enum && !schema.enum.some((item) => canonicalText(item) === canonicalText(value))) {
    fail(`${where} is outside the allowed enum`);
  }
  if (schema.type === "object") {
    const properties = schema.properties || {};
    for (const key of schema.required || []) {
      if (!Object.hasOwn(value, key)) fail(`${where} is missing required fields: ${key}`);
    }
    for (const key of Object.keys(value)) {
      if (!Object.hasOwn(properties, key)) {
        if (schema.additionalProperties === false) fail(`${where} has unknown fields: ${key}`);
      } else validateSchema(value[key], properties[key], `${where}.${key}`);
    }
  } else if (schema.type === "array") {
    if (schema.minItems !== undefined && value.length < schema.minItems) fail(`${where} has too few items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) fail(`${where} has too many items`);
    value.forEach((item, index) => validateSchema(item, schema.items, `${where}[${index}]`));
  } else if (schema.type === "string") {
    const length = Array.from(value).length;
    if (schema.minLength !== undefined && length < schema.minLength) fail(`${where} is too short`);
    if (schema.maxLength !== undefined && length > schema.maxLength) fail(`${where} is too long`);
  } else if (schema.type === "integer") {
    if (schema.minimum !== undefined && value < schema.minimum) fail(`${where} is below the minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) fail(`${where} exceeds the maximum`);
  }
}
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const locale = /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}$/;
const sha256 = /^sha256:[0-9a-f]{64}$/;
const mediaType = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;
const whitespace = /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;
function match(value, pattern, where) {
  const found = typeof value === "string" ? value.match(pattern) : null;
  if (!found || found[0] !== value) fail(`${where} is invalid`);
}
function documentSize(value, where, maximum = 1048576) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${where} must be an object`);
  if (Buffer.byteLength(canonicalText(value), "utf8") > maximum) fail(`${where} exceeds ${maximum} canonical UTF-8 bytes`);
}
function validateText(value, where, maximum = 8192, multiline = false, allowEmpty = false) {
  if (typeof value !== "string" || (!allowEmpty && whitespace.test(value))) fail(`${where} must be non-empty text`);
  if (Buffer.byteLength(value, "utf8") > maximum) fail(`${where} exceeds the UTF-8 byte limit`);
  for (const char of value) {
    const point = char.codePointAt(0);
    if ((point < 32 && !(multiline && [9, 10, 13].includes(point))) || point === 127) {
      fail(`${where} contains unsupported control characters`);
    }
  }
}
function validateAttachments(items) {
  const digests = items.map((item) => item.digest);
  for (const item of items) {
    match(item.digest, sha256, "attachment.digest");
    match(item.media_type, mediaType, "attachment.media_type");
    validateText(item.name, "attachment.name", 8192, false, true);
  }
  if (new Set(digests).size !== digests.length) fail("digests must be unique");
}
function validateInput(request) {
  documentSize(request, "$input");
  validateSchema(request, inputSchema, "$input");
  if (request.operation === "probe") {
    if (Object.keys(request).length !== 1) fail("probe accepts only operation");
    return;
  }
  const required = ["attachments", "automation_ceiling", "locale", "operation", "request_id", "source_kind", "source_text"];
  if (canonicalText(Object.keys(request).sort()) !== canonicalText(required)) fail("resolve has missing or unknown fields");
  match(request.request_id, identifier, "request_id");
  match(request.locale, locale, "locale");
  validateText(request.source_text, "source_text", 32768, true);
  validateAttachments(request.attachments);
}
function validateDraft(draft) {
  documentSize(draft, "$draft", 131072);
  validateSchema(draft, draftSchema, "$draft");
  if (draft.format !== "org.nth-dao.intent-draft") fail("format");
  if (draft.authority !== "none" || draft.commit_authority !== false
      || draft.executable !== false || draft.review_required !== true) {
    fail("review-only");
  }
  match(draft.request_id, identifier, "request_id");
  match(draft.locale, locale, "locale");
  match(draft.request_digest, sha256, "request_digest");
  validateText(draft.source_text, "source_text", 32768, true);
  validateText(draft.summary, "summary", 8192, true);
  validateAttachments(draft.attachments);
  for (const field of ["outcomes", "assumptions", "constraints", "risks"]) {
    for (const item of draft[field]) validateText(item, field, 8192, true);
  }
  const capabilities = draft.requested_capabilities;
  const sortedCapabilities = [...new Set(capabilities)].sort();
  if (canonicalText(capabilities) !== canonicalText(sortedCapabilities)) {
    fail("sorted and unique");
  }
  for (const cap of capabilities) match(cap, identifier, "requested_capabilities");
  const codes = draft.clarifications.map((item) => item.code);
  for (const item of draft.clarifications) {
    match(item.code, identifier, "clarification.code");
    validateText(item.question, "clarification.question", 8192, true);
  }
  if (new Set(codes).size !== codes.length) fail("clarification codes must be unique");
}
function parseDraft(text) {
  if (Buffer.byteLength(text, "utf8") > 131072) fail("draft_json exceeds the UTF-8 byte limit");
  let draft;
  try { draft = JSON.parse(text); } catch { fail("draft_json must contain valid JSON"); }
  validateDraft(draft);
  if (canonicalText(draft) !== text) fail("draft_json must use canonical JSON encoding");
  return draft;
}
function validateOutput(response) {
  documentSize(response, "$output");
  validateSchema(response, outputSchema, "$output");
  match(response.resolver_id, identifier, "resolver_id");
  if (canonicalText(response.supported_automation_levels) !== canonicalText(["A0", "A1", "A2", "A3", "A4"])) {
    fail("automation levels are incomplete or unordered");
  }
  if (response.max_source_bytes > 32768) fail("max_source_bytes exceeds the wire limit");
  if (response.max_attachments > 16) fail("max_attachments exceeds the wire limit");
  if (!response.ready || response.detail) fail("reference operation must be ready without detail");
  if (response.authority !== "none" || response.commit_authority !== false
      || response.executable !== false) {
    fail("cannot grant authority or execution");
  }
  match(response.invocation_context_digest, sha256, "invocation_context_digest");
  if (response.operation === "probe") {
    if (["draft_json", "draft_sha256", "request_digest", "request_id", "status"].some((field) => response[field])) {
      fail("probe cannot carry draft state");
    }
    return;
  }
  const draft = parseDraft(response.draft_json);
  if (digest(response.draft_json) !== response.draft_sha256) {
    fail("draft_sha256 does not bind");
  }
  if (response.request_id !== draft.request_id) fail("request_id does not bind draft_json");
  if (response.request_digest !== draft.request_digest) {
    fail("request_digest does not bind draft_json");
  }
  if (response.status !== (draft.clarifications.length ? "needs-clarification" : "draft")) {
    fail("status does not match draft clarifications");
  }
}
function validateExchange(request, response) {
  if (request.operation !== response.operation) fail("operation");
  if (request.operation === "probe") return;
  validateInput(request);
  const requestDigest = digest(canonicalText(request));
  if (request.request_id !== response.request_id) fail("request_id does not match");
  if (requestDigest !== response.request_digest) fail("request_digest");
  const draft = parseDraft(response.draft_json);
  for (const field of ["attachments", "automation_ceiling", "locale", "request_id",
                       "source_kind", "source_text"]) {
    if (canonicalText(draft[field]) !== canonicalText(request[field])) fail(field);
  }
}
function validateContext(response, context) {
  const keys = ["capability_id", "format", "invocation_id", "plugin_id", "principal"];
  if (context === null || typeof context !== "object" || Array.isArray(context)
      || canonicalText(Object.keys(context).sort()) !== canonicalText(keys)) fail("context has missing or unknown fields");
  if (context.format !== "org.nth-dao.intent-resolver-invocation-context.v1") fail("context.format is invalid");
  for (const field of ["plugin_id", "capability_id", "invocation_id"]) match(context[field], identifier, field);
  if (context.capability_id !== "org.nth-dao.intent.resolve") fail("context.capability_id is invalid");
  validateText(context.principal, "principal", 512);
  if (digest(canonicalText(context)) !== response.invocation_context_digest) {
    fail("does not bind Host invocation context");
  }
}
function validateAuthority(request, authority) {
  const keys = ["capability_ids", "idempotency_key", "mandate_digest", "principal", "resource_ids"];
  if (authority === null || typeof authority !== "object" || Array.isArray(authority)
      || canonicalText(Object.keys(authority).sort()) !== canonicalText(keys)) fail("authority shape");
  validateText(authority.principal, "authority principal", 512);
  if (!Array.isArray(authority.capability_ids) || authority.capability_ids.length === 0
      || authority.capability_ids.some(item => typeof item !== "string")) fail("authority capability scope");
  if (!authority.capability_ids.includes("org.nth-dao.intent.resolve")) fail("lacks capability scope");
  if (typeof authority.mandate_digest !== "string"
      || typeof authority.idempotency_key !== "string"
      || !Array.isArray(authority.resource_ids)) fail("authority business scope shape");
  if (authority.mandate_digest || authority.idempotency_key || authority.resource_ids.length) {
    fail("must not receive mandate, idempotency, or resource authority");
  }
}
for (const request of vector.positive_inputs) validateInput(request);
for (const response of vector.positive_outputs) validateOutput(response);
for (const item of vector.positive_exchanges) {
  validateAuthority(item.request, item.authority);
  validateOutput(item.response);
  validateExchange(item.request, item.response);
  validateContext(item.response, item.context);
}
for (const item of vector.negative_outputs) {
  let rejected = false;
  try { validateOutput(item.output); }
  catch (error) { if (!(error instanceof ValidationError)) throw error; rejected = true; }
  if (!rejected) fail(`negative output accepted: ${item.name}`);
}
for (const item of vector.negative_inputs) {
  let rejected = false;
  try { validateInput(item.input); }
  catch (error) { if (!(error instanceof ValidationError)) throw error; rejected = true; }
  if (!rejected) fail(`negative input accepted: ${item.name}`);
}
for (const item of vector.negative_authorities) {
  let rejected = false;
  try { validateAuthority(item.request, item.authority); }
  catch (error) { if (!(error instanceof ValidationError)) throw error; rejected = true; }
  if (!rejected) fail(`negative authority accepted: ${item.name}`);
}
for (const item of vector.negative_exchanges) {
  let rejected = false;
  validateOutput(item.response);
  try { validateExchange(item.request, item.response); }
  catch (error) { if (!(error instanceof ValidationError)) throw error; rejected = true; }
  if (!rejected) fail(`negative exchange accepted: ${item.name}`);
}
for (const item of vector.negative_context_bindings) {
  let rejected = false;
  validateOutput(item.response);
  try { validateContext(item.response, item.context); }
  catch (error) { if (!(error instanceof ValidationError)) throw error; rejected = true; }
  if (!rejected) fail(`negative context accepted: ${item.name}`);
}
for (const item of vector.negative_schemas) {
  let rejected = false;
  try { validateDefinition(item.schema); }
  catch (error) { if (!(error instanceof ValidationError)) throw error; rejected = true; }
  if (!rejected) fail(`negative schema accepted: ${item.name}`);
}
process.stdout.write("ok");
"""
    completed = subprocess.run(
        [
            shutil.which("node") or "node",
            "-e",
            script,
            str(VECTOR_DIR / "intent-resolver-wire-cases-v1.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "ok"


def test_intent_draft_is_canonical_content_addressed_and_request_bound() -> None:
    exchange = _resolve_exchange()
    request = exchange["request"]
    response = exchange["response"]
    document, encoded = canonical_intent_draft(response["draft_json"])

    assert encoded == response["draft_json"].encode("utf-8")
    assert response["draft_sha256"] == intent_draft_digest(response["draft_json"])
    assert response["invocation_context_digest"] == (
        intent_resolver_invocation_context_digest(exchange["context"])
    )
    assert document["request_digest"] == intent_resolver_request_digest(request)
    assert document["format"] == INTENT_DRAFT_FORMAT
    assert document["source_text"] == request["source_text"]
    assert document["authority"] == "none"
    assert document["executable"] is False
    assert document["commit_authority"] is False
    assert document["review_required"] is True

    noncanonical = json.dumps(document, ensure_ascii=False)
    assert noncanonical.encode("utf-8") != encoded
    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_intent_draft(noncanonical)


def test_intent_resolver_input_is_closed_and_utf8_bounded() -> None:
    request = copy.deepcopy(_resolve_exchange()["request"])
    with pytest.raises(PluginSchemaError, match="unknown fields"):
        validate_intent_resolver_input({**request, "mandate_id": "forbidden"})
    with pytest.raises(PluginSchemaError, match="accepts only operation"):
        validate_intent_resolver_input({"operation": "probe", "request_id": "bad"})

    request["source_text"] = " \n\t "
    with pytest.raises(PluginSchemaError, match="non-empty text"):
        validate_intent_resolver_input(request)

    request["source_text"] = "\u754c" * (INTENT_RESOLVER_MAX_SOURCE_BYTES // 2)
    with pytest.raises(PluginSchemaError, match="UTF-8 byte limit"):
        validate_intent_resolver_input(request)


def test_intent_resolver_attachments_are_explicitly_unverified_claims() -> None:
    request = copy.deepcopy(_resolve_exchange()["request"])
    assert request["attachments"][0]["verification_status"] == "unverified"

    missing = copy.deepcopy(request)
    missing["attachments"][0].pop("verification_status")
    with pytest.raises(PluginSchemaError):
        validate_intent_resolver_input(missing)

    forged = copy.deepcopy(request)
    forged["attachments"][0]["verification_status"] = "verified"
    with pytest.raises(PluginSchemaError):
        validate_intent_resolver_input(forged)


def test_intent_resolver_exact_source_and_attachment_limits() -> None:
    request = copy.deepcopy(_resolve_exchange()["request"])
    request["source_text"] = (
        "\u754c" * (INTENT_RESOLVER_MAX_SOURCE_BYTES // 3)
        + "a" * (INTENT_RESOLVER_MAX_SOURCE_BYTES % 3)
    )
    request["attachments"] = [
        {
            **request["attachments"][0],
            "digest": "sha256:" + f"{index:064x}",
        }
        for index in range(INTENT_RESOLVER_MAX_ATTACHMENTS)
    ]
    validate_intent_resolver_input(request)

    oversized_source = {**request, "source_text": request["source_text"] + "a"}
    with pytest.raises(PluginSchemaError, match="UTF-8 byte limit"):
        validate_intent_resolver_input(oversized_source)

    too_many = copy.deepcopy(request)
    too_many["attachments"].append(
        {**request["attachments"][0], "digest": "sha256:" + "f" * 64}
    )
    with pytest.raises(PluginSchemaError):
        validate_intent_resolver_input(too_many)


def test_intent_draft_exact_canonical_byte_limit() -> None:
    document = json.loads(_resolve_exchange()["response"]["draft_json"])
    fields = ("assumptions", "constraints", "outcomes", "risks")
    for field in fields:
        document[field] = ["x"] * 32
    remaining = INTENT_RESOLVER_MAX_DRAFT_BYTES - len(canonical_json(document))
    for field in fields:
        for index in range(32):
            added = min(1_999, remaining)
            document[field][index] += "x" * added
            remaining -= added
    assert remaining == 0

    encoded = canonical_json(document)
    assert len(encoded) == INTENT_RESOLVER_MAX_DRAFT_BYTES
    canonical_intent_draft(encoded.decode("utf-8"))

    document["risks"][-1] += "x"
    oversized = canonical_json(document)
    assert len(oversized) == INTENT_RESOLVER_MAX_DRAFT_BYTES + 1
    with pytest.raises(ValueError, match="UTF-8 byte limit"):
        canonical_intent_draft(oversized.decode("utf-8"))


def test_intent_output_validation_parses_draft_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import nth_dao.plugins.intent_resolver as resolver_module

    response = _resolve_exchange()["response"]
    original = resolver_module.canonical_intent_draft
    calls = 0

    def counted(value):
        nonlocal calls
        calls += 1
        return original(value)

    monkeypatch.setattr(resolver_module, "canonical_intent_draft", counted)
    validate_intent_resolver_output(response)
    assert calls == 1


def test_intent_draft_rejects_authority_smuggling_and_ambiguous_collections() -> None:
    document = json.loads(_resolve_exchange()["response"]["draft_json"])
    for mutation in (
        {"executable": True},
        {"commit_authority": True},
        {"authority": "none", "review_required": False},
    ):
        candidate = {**document, **mutation}
        with pytest.raises(PluginSchemaError, match="review-only"):
            validate_intent_draft(candidate)

    duplicate_capability = {
        **document,
        "requested_capabilities": ["code.review", "code.review"],
    }
    with pytest.raises(PluginSchemaError, match="sorted and unique"):
        validate_intent_draft(duplicate_capability)

    duplicate_attachment = {
        **document,
        "attachments": [document["attachments"][0], document["attachments"][0]],
    }
    with pytest.raises(PluginSchemaError, match="digests must be unique"):
        validate_intent_draft(duplicate_attachment)

    whitespace_assumption = {**document, "assumptions": [" \t "]}
    with pytest.raises(PluginSchemaError, match="non-empty text"):
        validate_intent_draft(whitespace_assumption)

    for mutation in (
        {key: value for key, value in document.items() if key != "format"},
        {**document, "format": "intent-draft"},
    ):
        with pytest.raises(PluginSchemaError):
            validate_intent_draft(mutation)


def test_intent_resolver_exchange_rejects_source_or_request_rebinding() -> None:
    exchange = _resolve_exchange()
    request = exchange["request"]
    response = exchange["response"]

    with pytest.raises(PluginSchemaError, match="request_digest"):
        validate_intent_resolver_exchange(
            {**request, "source_text": "A different request"},
            response,
        )

    draft = json.loads(response["draft_json"])
    draft["attachments"] = []
    rebound = {
        **response,
        "draft_json": canonical_json(draft).decode("utf-8"),
    }
    rebound["draft_sha256"] = intent_draft_digest(rebound["draft_json"])
    validate_intent_resolver_output(rebound)
    with pytest.raises(PluginSchemaError, match="attachments"):
        validate_intent_resolver_exchange(request, rebound)
