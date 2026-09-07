"""Generate deterministic Intent solver contract vectors.

The fixture reuses the public test-only signed IntentEnvelope vector.  It never
loads a local identity or writes outside ``nth_dao/plugins/vectors``.
"""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.plugins.host import InvocationAuthority, PluginInvocationContext
from nth_dao.plugins.intent_solver import (
    INTENT_SOLVER_CAPABILITY_ID,
    INTENT_SOLVER_CONTRACT,
    INTENT_SOLVER_INPUT_SCHEMA,
    INTENT_SOLVER_OUTPUT_SCHEMA,
    SOLVER_PROPOSAL_SCHEMA,
    canonical_signed_intent_envelope,
    intent_solver_protocol_digest,
    intent_solver_protocol_document,
)
from nth_dao.plugins.builtin.review_intent_solver import (
    REVIEW_INTENT_SOLVER_CLASS,
    REVIEW_INTENT_SOLVER_PLUGIN_ID,
    ReviewIntentSolverProvider,
)


ROOT = Path(__file__).parents[1]
VECTOR_ROOT = ROOT / "nth_dao" / "plugins" / "vectors"


def _hash(label: str) -> str:
    return "sha256:" + hashlib.sha256(("PUBLIC-NTH-TEST-ONLY:" + label).encode()).hexdigest()


def _envelope() -> dict:
    vectors = json.loads(
        (VECTOR_ROOT / "intent-envelope-wire-cases-v1.json").read_text(encoding="utf-8")
    )
    return deepcopy(vectors["positive_cases"][0]["envelope"])


def _evidence() -> dict:
    content = b"PUBLIC-NTH-TEST-ONLY:intent-solver-host-evidence-v1"
    return {
        "content_base64": base64.b64encode(content).decode("ascii"),
        "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
        "media_type": "text/plain",
        "observed_at_ms": 1_500,
        "provenance": "invocation-materialized",
        "source_kind": "artifact",
        "source_ref": "artifact:public-test-requirements",
        "verification_status": "content-verified",
    }


def _request() -> dict:
    envelope_json = canonical_json(_envelope()).decode()
    _document, _encoded, envelope_digest = canonical_signed_intent_envelope(envelope_json)
    return {
        "acceptance_audit_digest": _hash("intent-solver-acceptance-audit-v1"),
        "evidence": [_evidence()],
        "expires_at_ms": 60_000,
        "intent_envelope_digest": envelope_digest,
        "intent_envelope_json": envelope_json,
        "operation": "propose",
        "policy_snapshot_digest": _hash("intent-solver-policy-v1"),
        "proposal_id": "proposal:conformance-alpha",
        "proposed_at_ms": 2_000,
        "solver_class": REVIEW_INTENT_SOLVER_CLASS,
    }


def _authority(request: dict | None = None) -> InvocationAuthority:
    if request is None:
        return InvocationAuthority(
            principal="workspace:conformance-intent",
            capability_ids=frozenset({INTENT_SOLVER_CAPABILITY_ID}),
        )
    return InvocationAuthority(
        principal="workspace:conformance-intent",
        capability_ids=frozenset({INTENT_SOLVER_CAPABILITY_ID}),
        mandate_digest=request["acceptance_audit_digest"],
        idempotency_key=request["proposal_id"],
        resource_ids=frozenset(
            {
                request["intent_envelope_digest"],
                request["policy_snapshot_digest"],
                *(item["digest"] for item in request["evidence"]),
            }
        ),
    )


def _authority_dict(authority: InvocationAuthority) -> dict:
    return {
        "capability_ids": sorted(authority.capability_ids),
        "idempotency_key": authority.idempotency_key,
        "mandate_digest": authority.mandate_digest,
        "principal": authority.principal,
        "resource_ids": sorted(authority.resource_ids),
    }


def _context(request: dict | None = None) -> PluginInvocationContext:
    return PluginInvocationContext(
        plugin_id=REVIEW_INTENT_SOLVER_PLUGIN_ID,
        capability_id=INTENT_SOLVER_CAPABILITY_ID,
        invocation_id="0123456789abcdef0123456789abcdef",
        authority=_authority(request),
        granted_permissions=frozenset(),
        workspace_root=None,
    )


def _response_with_proposal(response: dict, proposal: dict) -> dict:
    proposal_json = canonical_json(proposal).decode()
    return response | {
        "proposal_json": proposal_json,
        "proposal_sha256": "sha256:" + hashlib.sha256(proposal_json.encode()).hexdigest(),
    }


def build_vectors() -> dict:
    provider = ReviewIntentSolverProvider()
    request = _request()
    context = _context(request)
    probe_context = _context()
    response = dict(provider.invoke(request, context))
    probe = dict(provider.invoke({"operation": "probe"}, probe_context))
    context_document = provider._context_document(context)
    probe_context_document = provider._context_document(probe_context)
    proposal = json.loads(response["proposal_json"])

    unknown_input = request | {"payment_grant": True}
    noncanonical_envelope = request | {
        "intent_envelope_json": json.dumps(_envelope(), ensure_ascii=False),
    }
    tampered_envelope = _envelope()
    tampered_envelope["scope_id"] = "workspace:tampered"
    tampered_input = request | {
        "intent_envelope_json": canonical_json(tampered_envelope).decode(),
    }
    bad_evidence = deepcopy(request)
    bad_evidence["evidence"][0]["verification_status"] = "unverified"
    duplicate_evidence = deepcopy(request)
    duplicate_evidence["evidence"] *= 2
    envelope, _encoded, _digest = canonical_signed_intent_envelope(
        request["intent_envelope_json"]
    )
    duplicate_draft = deepcopy(request)
    duplicate_draft["evidence"][0]["digest"] = envelope["draft_digest"]
    future_evidence = deepcopy(request)
    future_evidence["evidence"][0]["observed_at_ms"] = request["proposed_at_ms"] + 1
    tampered_material = deepcopy(request)
    tampered_material["evidence"][0]["content_base64"] = base64.b64encode(
        b"different content"
    ).decode("ascii")
    multiline_source_ref = deepcopy(request)
    multiline_source_ref["evidence"][0]["source_ref"] = "artifact:alpha\nforged"

    executable = response | {"executable": True}
    wrong_digest = response | {"proposal_sha256": _hash("wrong-proposal")}
    unknown_evidence_proposal = deepcopy(proposal)
    unknown_evidence_proposal["facts"][0]["evidence_digests"] = [_hash("unknown")]
    authority_proposal = proposal | {"commit_authority": True}
    duplicate_classes = response | {
        "supported_solver_classes": [REVIEW_INTENT_SOLVER_CLASS] * 2,
    }
    bad_did = proposal | {"solver_did": "did:key:not-valid"}
    low_order_did = proposal | {
        "solver_did": encode_ed25519_did_key(b"\x01" + bytes(31)),
    }
    future_proposal_evidence = deepcopy(proposal)
    future_proposal_evidence["evidence"][0]["observed_at_ms"] = (
        proposal["created_at_ms"] + 1
    )

    permission_expansion = proposal | {"requested_permissions": ["payment.commit"]}
    wrong_policy = proposal | {"policy_snapshot_digest": _hash("other-policy")}
    dropped_host = deepcopy(proposal)
    dropped_host["evidence"] = [
        item for item in dropped_host["evidence"] if item["digest"] != _evidence()["digest"]
    ]
    wrong_id = proposal | {"proposal_id": "proposal:other"}

    wrong_principal_context = context_document | {"principal": "workspace:other"}
    wrong_plugin_context = context_document | {
        "plugin_id": "org.nth-dao.intent.other-solver"
    }
    extra_context_resource = context_document | {
        "resource_ids": sorted([*context_document["resource_ids"], _hash("extra-resource")])
    }

    propose_authority = _authority(request)
    negative_authorities = [
        (
            "wrong-acceptance-audit",
            InvocationAuthority(
                principal=propose_authority.principal,
                capability_ids=propose_authority.capability_ids,
                mandate_digest=_hash("other-audit"),
                idempotency_key=propose_authority.idempotency_key,
                resource_ids=propose_authority.resource_ids,
            ),
        ),
        (
            "wrong-idempotency",
            InvocationAuthority(
                principal=propose_authority.principal,
                capability_ids=propose_authority.capability_ids,
                mandate_digest=propose_authority.mandate_digest,
                idempotency_key="proposal:other",
                resource_ids=propose_authority.resource_ids,
            ),
        ),
        (
            "extra-resource-scope",
            InvocationAuthority(
                principal=propose_authority.principal,
                capability_ids=propose_authority.capability_ids,
                mandate_digest=propose_authority.mandate_digest,
                idempotency_key=propose_authority.idempotency_key,
                resource_ids=frozenset({*propose_authority.resource_ids, _hash("extra")}),
            ),
        ),
        (
            "wrong-capability",
            InvocationAuthority(
                principal=propose_authority.principal,
                capability_ids=frozenset({"org.example.other"}),
                mandate_digest=propose_authority.mandate_digest,
                idempotency_key=propose_authority.idempotency_key,
                resource_ids=propose_authority.resource_ids,
            ),
        ),
    ]
    probe_business = InvocationAuthority(
        principal="workspace:conformance-intent",
        capability_ids=frozenset({INTENT_SOLVER_CAPABILITY_ID}),
        mandate_digest=_hash("probe-must-not-carry-this"),
    )
    request_json = canonical_json(request).decode()
    response_json = canonical_json(response).decode()
    proposal_json = response["proposal_json"]

    return {
        "format": "org.nth-dao.intent-solver-conformance.v1",
        "protocol_digest": intent_solver_protocol_digest(),
        "positive_inputs": [{"operation": "probe"}, request],
        "positive_outputs": [probe, response],
        "positive_exchanges": [
            {
                "authority": _authority_dict(_authority()),
                "context": probe_context_document,
                "request": {"operation": "probe"},
                "response": probe,
            },
            {
                "authority": _authority_dict(propose_authority),
                "context": context_document,
                "request": request,
                "response": response,
            },
        ],
        "negative_inputs": [
            {"name": "unknown-field", "input": unknown_input},
            {"name": "noncanonical-envelope", "input": noncanonical_envelope},
            {"name": "signature-tampered-envelope", "input": tampered_input},
            {"name": "unaccepted-solver-class", "input": request | {"solver_class": "org.nth-dao.solver.other"}},
            {"name": "outside-envelope-time", "input": request | {"expires_at_ms": 61_001}},
            {"name": "boolean-time", "input": request | {"proposed_at_ms": True}},
            {"name": "evidence-provenance-conflict", "input": bad_evidence},
            {"name": "duplicate-evidence", "input": duplicate_evidence},
            {"name": "duplicate-draft-evidence", "input": duplicate_draft},
            {"name": "future-evidence", "input": future_evidence},
            {"name": "evidence-content-digest-mismatch", "input": tampered_material},
            {"name": "multiline-source-ref", "input": multiline_source_ref},
        ],
        "negative_outputs": [
            {"name": "executable-wrapper", "output": executable},
            {"name": "wrong-proposal-digest", "output": wrong_digest},
            {"name": "unknown-evidence-reference", "output": _response_with_proposal(response, unknown_evidence_proposal)},
            {"name": "proposal-commit-authority", "output": _response_with_proposal(response, authority_proposal)},
            {"name": "duplicate-supported-classes", "output": duplicate_classes},
            {"name": "invalid-solver-did", "output": _response_with_proposal(response, bad_did)},
            {"name": "low-order-solver-did", "output": _response_with_proposal(response, low_order_did)},
            {"name": "future-proposal-evidence", "output": _response_with_proposal(response, future_proposal_evidence)},
        ],
        "negative_exchanges": [
            {"name": "permission-expansion", "request": request, "response": _response_with_proposal(response, permission_expansion)},
            {"name": "policy-rebinding", "request": request, "response": _response_with_proposal(response, wrong_policy)},
            {"name": "host-evidence-dropped", "request": request, "response": _response_with_proposal(response, dropped_host)},
            {"name": "proposal-id-rebinding", "request": request, "response": _response_with_proposal(response, wrong_id)},
            {
                "name": "unsupported-solver-class",
                "request": request,
                "response": response | {
                    "supported_solver_classes": ["org.nth-dao.solver.other"]
                },
            },
        ],
        "negative_context_bindings": [
            {"name": "principal-replay", "context": wrong_principal_context, "response": response},
            {"name": "plugin-replay", "context": wrong_plugin_context, "response": response},
            {"name": "resource-replay", "context": extra_context_resource, "response": response},
        ],
        "negative_authorities": [
            *(
                {"name": name, "authority": _authority_dict(authority), "request": request}
                for name, authority in negative_authorities
            ),
            {"name": "probe-business-authority", "authority": _authority_dict(probe_business), "request": {"operation": "probe"}},
        ],
        "raw_negative_inputs": [
            {
                "name": "proposed-at-exponent-token",
                "input_json": request_json.replace(
                    '"proposed_at_ms":2000', '"proposed_at_ms":2e3', 1
                ),
            },
            {
                "name": "proposed-at-decimal-token",
                "input_json": request_json.replace(
                    '"proposed_at_ms":2000', '"proposed_at_ms":2000.0', 1
                ),
            },
            {
                "name": "evidence-negative-zero-decimal-token",
                "input_json": request_json.replace(
                    '"observed_at_ms":1500', '"observed_at_ms":-0.0', 1
                ),
            },
            {
                "name": "expires-at-unsafe-integer",
                "input_json": request_json.replace(
                    '"expires_at_ms":60000', '"expires_at_ms":9007199254740992', 1
                ),
            },
        ],
        "raw_negative_outputs": [
            {
                "name": "max-evidence-exponent-token",
                "output_json": response_json.replace(
                    '"max_evidence":32', '"max_evidence":3.2e1', 1
                ),
            },
            {
                "name": "max-proposal-bytes-decimal-token",
                "output_json": response_json.replace(
                    '"max_proposal_bytes":262144', '"max_proposal_bytes":262144.0', 1
                ),
            },
        ],
        "raw_negative_proposals": [
            {
                "name": "created-at-exponent-token",
                "proposal_json": proposal_json.replace(
                    '"created_at_ms":2000', '"created_at_ms":2e3', 1
                ),
            },
            {
                "name": "created-at-decimal-token",
                "proposal_json": proposal_json.replace(
                    '"created_at_ms":2000', '"created_at_ms":2000.0', 1
                ),
            },
        ],
    }


def vector_documents() -> dict[str, dict]:
    protocol = intent_solver_protocol_document()
    return {
        "intent-solver-capability-v1.json": INTENT_SOLVER_CONTRACT.to_dict(),
        "intent-solver-input-schema-v1.json": deepcopy(INTENT_SOLVER_INPUT_SCHEMA),
        "intent-solver-output-schema-v1.json": deepcopy(INTENT_SOLVER_OUTPUT_SCHEMA),
        "solver-proposal-schema-v1.json": deepcopy(SOLVER_PROPOSAL_SCHEMA),
        "intent-solver-wire-cases-v1.json": build_vectors(),
        "intent-solver-protocol-v1.json": protocol,
    }


def main() -> None:
    for name, document in vector_documents().items():
        (VECTOR_ROOT / name).write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
