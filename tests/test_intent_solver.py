"""Security and lifecycle tests for the review-only Intent solver boundary."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import threading
import time
import typing

import pytest

import nth_dao.plugins.intent_solver as intent_solver_module
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.plugins import (
    INTENT_SOLVER_CAPABILITY_ID,
    INTENT_SOLVER_CONTRACT,
    INTENT_SOLVER_INPUT_SCHEMA,
    INTENT_SOLVER_OUTPUT_SCHEMA,
    CapabilitySchemas,
    GovernedIntentSolverInvocation,
    InvocationAuthority,
    PluginContractError,
    PluginHost,
    PluginHostPolicy,
    PluginAuthorizationError,
    PluginInvocationContext,
    PluginInvocationError,
    PluginSchemaError,
    IntentSolverPreparationError,
    INTENT_RESOLVER_CONTRACT,
    accepted_intent_evidence,
    canonical_signed_intent_envelope,
    canonical_solver_proposal,
    intent_solver_invocation_context_digest,
    materialized_evidence_descriptor,
    prepare_governed_intent_solver_invocation,
    solver_proposal_digest,
    validate_intent_solver_authority,
    validate_intent_solver_context_binding,
    validate_intent_solver_exchange,
    validate_intent_solver_input,
    validate_intent_solver_output,
    validate_solver_proposal,
)
from nth_dao.plugins.intent_acceptance import IntentAcceptanceStore
from nth_dao.plugins.intent_envelope import intent_envelope_digest, sign_intent_envelope
from nth_dao.plugins.intent_policy import IntentAcceptancePolicySnapshot, IntentPolicyMember
from nth_dao.plugins.intent_policy_store import IntentPolicyStore
from nth_dao.plugins.builtin.review_intent_solver import (
    REVIEW_INTENT_SOLVER_CLASS,
    REVIEW_INTENT_SOLVER_PLUGIN_ID,
    ReviewIntentSolverPlugin,
    ReviewIntentSolverProvider,
    register_review_intent_solver,
    review_intent_solver_manifest,
)
from nth_dao.web import create_app
from tools.generate_intent_envelope_vectors import _test_identity


VECTOR_DIR = Path(__file__).parents[1] / "nth_dao" / "plugins" / "vectors"


def _hash(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _envelope() -> dict:
    vectors = json.loads(
        (VECTOR_DIR / "intent-envelope-wire-cases-v1.json").read_text(encoding="utf-8")
    )
    return deepcopy(vectors["positive_cases"][0]["envelope"])


def _evidence() -> dict:
    content = b"host-artifact-alpha"
    return {
        "content_base64": base64.b64encode(content).decode("ascii"),
        "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
        "media_type": "text/plain",
        "observed_at_ms": 1_500,
        "provenance": "invocation-materialized",
        "source_kind": "artifact",
        "source_ref": "artifact:requirements-alpha",
        "verification_status": "content-verified",
    }


def _request() -> dict:
    envelope = _envelope()
    envelope_json = canonical_json(envelope).decode()
    _document, _encoded, envelope_digest = canonical_signed_intent_envelope(envelope_json)
    return {
        "acceptance_audit_digest": _hash("acceptance-audit-alpha"),
        "evidence": [_evidence()],
        "expires_at_ms": 60_000,
        "intent_envelope_digest": envelope_digest,
        "intent_envelope_json": envelope_json,
        "operation": "propose",
        "policy_snapshot_digest": _hash("intent-policy-alpha"),
        "proposal_id": "proposal:alpha",
        "proposed_at_ms": 2_000,
        "solver_class": REVIEW_INTENT_SOLVER_CLASS,
    }


def _authority(request: dict | None = None) -> InvocationAuthority:
    if request is None:
        return InvocationAuthority(
            principal="workspace:alpha",
            capability_ids=frozenset({INTENT_SOLVER_CAPABILITY_ID}),
        )
    resources = {
        request["intent_envelope_digest"],
        request["policy_snapshot_digest"],
        *(item["digest"] for item in request["evidence"]),
    }
    return InvocationAuthority(
        principal="workspace:alpha",
        capability_ids=frozenset({INTENT_SOLVER_CAPABILITY_ID}),
        mandate_digest=request["acceptance_audit_digest"],
        idempotency_key=request["proposal_id"],
        resource_ids=frozenset(resources),
    )


def _context(request: dict | None = None) -> PluginInvocationContext:
    return PluginInvocationContext(
        plugin_id=REVIEW_INTENT_SOLVER_PLUGIN_ID,
        capability_id=INTENT_SOLVER_CAPABILITY_ID,
        invocation_id="0123456789abcdef0123456789abcdef",
        authority=_authority(request),
        granted_permissions=frozenset(),
        workspace_root=None,
    )


def _enabled_binding(tmp_path: Path):
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_review_intent_solver(host)
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    return host, item, binding


def _governed_state(tmp_path: Path):
    clock_value = [1_500]
    envelope = _envelope()
    member = IntentPolicyMember(
        signer_did=envelope["signer_did"],
        role="owner",
        status="active",
        allowed_solver_classes=(REVIEW_INTENT_SOLVER_CLASS,),
        automation_ceiling="A1",
    )
    policy = IntentAcceptancePolicySnapshot.create(
        audience_did=envelope["audience_did"],
        scope_id=envelope["scope_id"],
        reviewed_draft_digest=envelope["draft_digest"],
        membership_digest=_hash("solver-membership-v1"),
        revocation_digest=_hash("solver-revocations-v1"),
        policy_revision=1,
        previous_policy_digest="",
        issued_at_ms=1_000,
        expires_at_ms=60_000,
        allowed_acceptance_roles=("owner",),
        members=(member,),
    )
    acceptance_store = IntentAcceptanceStore(tmp_path, clock=lambda: clock_value[0])
    policy_store = IntentPolicyStore(tmp_path, clock=lambda: clock_value[0])
    published = policy_store.publish(policy)
    accepted = acceptance_store.accept_governed(
        envelope,
        policy_store=policy_store,
        signer_did=envelope["signer_did"],
        expected_policy_tail_digest=published.record.audit_digest,
    )
    return clock_value, envelope, policy, acceptance_store, policy_store, accepted.record


def test_solver_contract_is_confidential_non_authoritative_and_exported() -> None:
    assert INTENT_SOLVER_CAPABILITY_ID == "org.nth-dao.intent.propose"
    assert INTENT_SOLVER_CONTRACT.effects == ("none",)
    assert INTENT_SOLVER_CONTRACT.consistency == "C0"
    assert INTENT_SOLVER_CONTRACT.privacy == "confidential"
    assert INTENT_SOLVER_CONTRACT.security == "untrusted-hint"
    assert INTENT_SOLVER_CONTRACT.retention == "none"
    assert "INTENT_SOLVER_MAX_SAFE_INTEGER" in intent_solver_module.__all__
    hints = typing.get_type_hints(GovernedIntentSolverInvocation)
    assert hints["_acceptance_store"] is IntentAcceptanceStore
    assert hints["_policy_store"] is IntentPolicyStore


def test_review_solver_is_installed_but_disabled_by_default(tmp_path: Path) -> None:
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_review_intent_solver(host)

    assert host.status(item.plugin_id).state == "installed"
    assert host.status(item.plugin_id).risk_tier == 0
    assert host.resolve(INTENT_SOLVER_CAPABILITY_ID) == ()


def test_web_registers_review_solver_without_enabling_it(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    host = app.state.nth.plugin_host

    status = host.status(REVIEW_INTENT_SOLVER_PLUGIN_ID)
    assert status.state == "installed"
    assert status.desired_enabled is False
    assert host.resolve(INTENT_SOLVER_CAPABILITY_ID) == ()


def test_review_solver_manifest_has_no_permissions_or_effects() -> None:
    item = review_intent_solver_manifest()

    assert item.kind == "intent.solver"
    assert item.permissions == ()
    assert item.requires == ()
    assert item.provides == (INTENT_SOLVER_CONTRACT,)


@pytest.mark.parametrize(
    "missing",
    (
        "input_validator",
        "output_validator",
        "exchange_validator",
        "authority_validator",
        "response_context_validator",
    ),
)
def test_host_requires_all_solver_security_boundaries(missing: str) -> None:
    validators = {
        "input_validator": lambda value: None,
        "output_validator": lambda value: None,
        "exchange_validator": lambda request, response: None,
        "authority_validator": lambda request, authority: None,
        "response_context_validator": lambda response, context: None,
    }
    validators[missing] = None
    host = PluginHost()

    with pytest.raises(PluginContractError, match="context-bound capability"):
        host.register_builtin(
            review_intent_solver_manifest(),
            ReviewIntentSolverPlugin,
            schemas={
                INTENT_SOLVER_CAPABILITY_ID: CapabilitySchemas(
                    INTENT_SOLVER_INPUT_SCHEMA,
                    INTENT_SOLVER_OUTPUT_SCHEMA,
                    **validators,
                )
            },
        )


def test_review_solver_probe_and_propose_through_host(tmp_path: Path) -> None:
    host, _item, binding = _enabled_binding(tmp_path)
    request = _request()

    probe = host.invoke(binding, {"operation": "probe"}, authority=_authority())
    response = host.invoke(binding, request, authority=_authority(request))
    proposal, canonical = canonical_solver_proposal(response["proposal_json"])
    envelope, _encoded, envelope_digest = canonical_signed_intent_envelope(
        request["intent_envelope_json"]
    )

    assert probe["proposal_json"] == ""
    assert response["status"] == "proposal"
    assert response["proposal_sha256"] == solver_proposal_digest(response["proposal_json"])
    assert canonical == response["proposal_json"].encode()
    assert proposal["intent_envelope_digest"] == envelope_digest
    assert proposal["draft_digest"] == envelope["draft_digest"]
    assert proposal["claim_status"] == "unverified"
    assert proposal["authority"] == "none"
    assert proposal["commit_authority"] is False
    assert proposal["executable"] is False
    assert proposal["review_required"] is True
    assert proposal["selection_required"] is True
    assert proposal["requested_permissions"] == []
    assert proposal["solver_plugin_id"] == REVIEW_INTENT_SOLVER_PLUGIN_ID
    assert proposal["solver_did"] == ""
    assert proposal["proposed_actions"] == json.loads(envelope["draft_json"])["outcomes"]
    assert proposal["facts"][0]["evidence_digests"] == [envelope["draft_digest"]]
    assert proposal["evidence"] == sorted(
        [
            accepted_intent_evidence(
                envelope,
                envelope_digest,
                observed_at_ms=request["proposed_at_ms"],
            ),
            materialized_evidence_descriptor(_evidence()),
        ],
        key=lambda item: item["digest"],
    )


def test_solver_validates_signed_documents_once_per_trust_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counts = {"envelope": 0, "proposal": 0}
    original_envelope = intent_solver_module.canonical_signed_intent_envelope
    original_proposal = intent_solver_module.canonical_solver_proposal

    def counted_envelope(*args, **kwargs):
        counts["envelope"] += 1
        return original_envelope(*args, **kwargs)

    def counted_proposal(*args, **kwargs):
        counts["proposal"] += 1
        return original_proposal(*args, **kwargs)

    monkeypatch.setattr(
        intent_solver_module,
        "canonical_signed_intent_envelope",
        counted_envelope,
    )
    monkeypatch.setattr(
        intent_solver_module,
        "canonical_solver_proposal",
        counted_proposal,
    )

    request = _request()
    counts.update(envelope=0, proposal=0)
    ReviewIntentSolverProvider().invoke(request, _context(request))
    assert counts == {"envelope": 1, "proposal": 1}

    host, _item, binding = _enabled_binding(tmp_path)
    counts.update(envelope=0, proposal=0)
    host.invoke(binding, request, authority=_authority(request))
    assert counts == {"envelope": 2, "proposal": 2}


def test_governed_builder_derives_current_request_and_invokes(tmp_path: Path) -> None:
    clock, envelope, policy, acceptances, policies, record = _governed_state(tmp_path)
    clock[0] = 2_000
    prepared = prepare_governed_intent_solver_invocation(
        acceptance_store=acceptances,
        policy_store=policies,
        envelope_digest=record.envelope_digest,
        proposal_id="proposal:governed-alpha",
        solver_class=REVIEW_INTENT_SOLVER_CLASS,
        evidence=[_evidence()],
        clock=lambda: clock[0],
    )

    assert isinstance(prepared, GovernedIntentSolverInvocation)
    assert prepared.request["acceptance_audit_digest"] == record.audit_digest
    assert prepared.request["policy_snapshot_digest"] == policy.digest
    assert prepared.request["proposed_at_ms"] == clock[0]
    assert prepared.authority.principal == envelope["audience_did"]
    assert prepared.authority.resource_ids == frozenset(
        {record.envelope_digest, policy.digest, _evidence()["digest"]}
    )
    host, _item, binding = _enabled_binding(tmp_path / "host")
    assert prepared.invoke(binding)["status"] == "proposal"


def test_governed_builder_rejects_stale_envelope_and_unknown_acceptance(
    tmp_path: Path,
) -> None:
    clock, _envelope, _policy, acceptances, policies, record = _governed_state(tmp_path)
    clock[0] = 60_000
    kwargs = {
        "acceptance_store": acceptances,
        "policy_store": policies,
        "proposal_id": "proposal:governed-alpha",
        "solver_class": REVIEW_INTENT_SOLVER_CLASS,
        "clock": lambda: clock[0],
    }

    with pytest.raises(IntentSolverPreparationError, match="not currently valid"):
        prepare_governed_intent_solver_invocation(
            envelope_digest=record.envelope_digest,
            **kwargs,
        )
    with pytest.raises(IntentSolverPreparationError, match="not in the verified journal"):
        prepare_governed_intent_solver_invocation(
            envelope_digest=_hash("not-accepted"),
            **kwargs,
        )


def test_governed_builder_rejects_policy_store_from_another_workspace(
    tmp_path: Path,
) -> None:
    clock, _envelope, _policy, acceptances, _policies, record = _governed_state(
        tmp_path / "accepted"
    )
    wrong_policy_store = IntentPolicyStore(
        tmp_path / "other",
        clock=lambda: clock[0],
    )

    with pytest.raises(IntentSolverPreparationError, match="same workspace"):
        prepare_governed_intent_solver_invocation(
            acceptance_store=acceptances,
            policy_store=wrong_policy_store,
            envelope_digest=record.envelope_digest,
            proposal_id="proposal:wrong-workspace",
            solver_class=REVIEW_INTENT_SOLVER_CLASS,
            clock=lambda: clock[0],
        )


def test_governed_builder_rejects_replaced_policy_head(tmp_path: Path) -> None:
    clock, envelope, policy, acceptances, policies, record = _governed_state(tmp_path)
    clock[0] = 2_000
    successor = IntentAcceptancePolicySnapshot.create(
        audience_did=envelope["audience_did"],
        scope_id=envelope["scope_id"],
        reviewed_draft_digest=envelope["draft_digest"],
        membership_digest=_hash("solver-membership-v2"),
        revocation_digest=_hash("solver-revocations-v2"),
        policy_revision=2,
        previous_policy_digest=policy.digest,
        issued_at_ms=1_900,
        expires_at_ms=60_000,
        allowed_acceptance_roles=("owner",),
        members=policy.members,
    )
    policies.publish(successor)

    with pytest.raises(IntentSolverPreparationError, match="policy.*current scope head"):
        prepare_governed_intent_solver_invocation(
            acceptance_store=acceptances,
            policy_store=policies,
            envelope_digest=record.envelope_digest,
            proposal_id="proposal:governed-alpha",
            solver_class=REVIEW_INTENT_SOLVER_CLASS,
            clock=lambda: clock[0],
        )


def test_prepared_solver_invocation_rechecks_policy_head_before_disclosure(
    tmp_path: Path,
) -> None:
    clock, envelope, policy, acceptances, policies, record = _governed_state(tmp_path)
    clock[0] = 2_000
    prepared = prepare_governed_intent_solver_invocation(
        acceptance_store=acceptances,
        policy_store=policies,
        envelope_digest=record.envelope_digest,
        proposal_id="proposal:governed-stale-policy",
        solver_class=REVIEW_INTENT_SOLVER_CLASS,
        evidence=[_evidence()],
        clock=lambda: clock[0],
    )
    policies.publish(
        IntentAcceptancePolicySnapshot.create(
            audience_did=envelope["audience_did"],
            scope_id=envelope["scope_id"],
            reviewed_draft_digest=envelope["draft_digest"],
            membership_digest=_hash("solver-membership-v2-after-prepare"),
            revocation_digest=_hash("solver-revocations-v2-after-prepare"),
            policy_revision=2,
            previous_policy_digest=policy.digest,
            issued_at_ms=1_900,
            expires_at_ms=60_000,
            allowed_acceptance_roles=("owner",),
            members=policy.members,
        )
    )
    _host, _item, binding = _enabled_binding(tmp_path / "host")

    with pytest.raises(IntentSolverPreparationError, match="policy.*current scope head"):
        prepared.invoke(binding)


def test_prepared_solver_invocation_rechecks_acceptance_head_before_disclosure(
    tmp_path: Path,
) -> None:
    clock, envelope, _policy, acceptances, policies, record = _governed_state(tmp_path)
    clock[0] = 2_000
    prepared = prepare_governed_intent_solver_invocation(
        acceptance_store=acceptances,
        policy_store=policies,
        envelope_digest=record.envelope_digest,
        proposal_id="proposal:governed-stale-acceptance",
        solver_class=REVIEW_INTENT_SOLVER_CLASS,
        evidence=[_evidence()],
        clock=lambda: clock[0],
    )
    successor_body = {key: value for key, value in envelope.items() if key != "signature"}
    successor_body.update(
        nonce="2" * 32,
        previous_digest=intent_envelope_digest(envelope),
        revision=2,
    )
    successor = sign_intent_envelope(
        successor_body,
        signer=_test_identity("intent-envelope-signer-v1"),
    )
    acceptances.accept_governed(
        successor,
        policy_store=policies,
        signer_did=successor["signer_did"],
        expected_policy_tail_digest=policies.history()[-1].audit_digest,
    )
    _host, _item, binding = _enabled_binding(tmp_path / "host")

    with pytest.raises(IntentSolverPreparationError, match="no longer the current scope head"):
        prepared.invoke(binding)


def test_prepared_solver_invocation_rechecks_time_and_is_single_use(
    tmp_path: Path,
) -> None:
    clock, _envelope, _policy, acceptances, policies, record = _governed_state(
        tmp_path / "valid"
    )
    clock[0] = 2_000
    prepared = prepare_governed_intent_solver_invocation(
        acceptance_store=acceptances,
        policy_store=policies,
        envelope_digest=record.envelope_digest,
        proposal_id="proposal:governed-single-use",
        solver_class=REVIEW_INTENT_SOLVER_CLASS,
        clock=lambda: clock[0],
    )
    _host, _item, binding = _enabled_binding(tmp_path / "valid-host")
    assert prepared.invoke(binding)["status"] == "proposal"
    with pytest.raises(IntentSolverPreparationError, match="already been consumed"):
        prepared.invoke(binding)

    clock, _envelope, _policy, acceptances, policies, record = _governed_state(
        tmp_path / "expired"
    )
    clock[0] = 2_000
    expired = prepare_governed_intent_solver_invocation(
        acceptance_store=acceptances,
        policy_store=policies,
        envelope_digest=record.envelope_digest,
        proposal_id="proposal:governed-expired",
        solver_class=REVIEW_INTENT_SOLVER_CLASS,
        clock=lambda: clock[0],
    )
    clock[0] = 60_000
    _host, _item, binding = _enabled_binding(tmp_path / "expired-host")
    with pytest.raises(IntentSolverPreparationError, match="not currently valid"):
        expired.invoke(binding)


def test_prepared_solver_invocation_rejects_wrong_contract_without_consuming(
    tmp_path: Path,
) -> None:
    clock, _envelope, _policy, acceptances, policies, record = _governed_state(tmp_path)
    clock[0] = 2_000
    prepared = prepare_governed_intent_solver_invocation(
        acceptance_store=acceptances,
        policy_store=policies,
        envelope_digest=record.envelope_digest,
        proposal_id="proposal:governed-contract",
        solver_class=REVIEW_INTENT_SOLVER_CLASS,
        clock=lambda: clock[0],
    )
    _host, _item, binding = _enabled_binding(tmp_path / "host")

    with pytest.raises(IntentSolverPreparationError, match="exact intent solver contract"):
        prepared.invoke(replace(binding, contract=INTENT_RESOLVER_CONTRACT))
    assert prepared.invoke(binding)["status"] == "proposal"


def test_prepared_solver_invocation_is_exactly_once_under_thread_race(
    tmp_path: Path,
) -> None:
    clock, _envelope, _policy, acceptances, policies, record = _governed_state(tmp_path)
    clock[0] = 2_000
    prepared = prepare_governed_intent_solver_invocation(
        acceptance_store=acceptances,
        policy_store=policies,
        envelope_digest=record.envelope_digest,
        proposal_id="proposal:governed-race",
        solver_class=REVIEW_INTENT_SOLVER_CLASS,
        clock=lambda: clock[0],
    )
    _host, _item, binding = _enabled_binding(tmp_path / "host")
    barrier = threading.Barrier(8)

    def invoke_once() -> str:
        barrier.wait(timeout=5)
        try:
            prepared.invoke(binding)
        except IntentSolverPreparationError as exc:
            assert "already been consumed" in str(exc)
            return "consumed"
        return "invoked"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _index: invoke_once(), range(8)))

    assert outcomes.count("invoked") == 1
    assert outcomes.count("consumed") == 7


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("mandate_digest", _hash("wrong-audit"), "acceptance audit"),
        ("idempotency_key", "proposal:other", "idempotency"),
        ("resource_ids", frozenset({_hash("other-resource")}), "resources"),
    ),
)
def test_solver_rejects_authority_rebinding(field: str, replacement, message: str) -> None:
    request = _request()
    authority = replace(_authority(request), **{field: replacement})

    with pytest.raises(PluginAuthorizationError, match=message):
        validate_intent_solver_authority(request, authority)


def test_solver_rejects_loose_or_business_authority_on_probe() -> None:
    with pytest.raises(PluginAuthorizationError, match="must not carry business authority"):
        validate_intent_solver_authority(
            {"operation": "probe"},
            InvocationAuthority(
                principal="workspace:alpha",
                capability_ids=frozenset({INTENT_SOLVER_CAPABILITY_ID}),
                mandate_digest=_hash("unexpected"),
            ),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ({"solver_class": "org.nth-dao.solver.not-accepted"}, "not allowed"),
        ({"proposed_at_ms": 999}, "validity"),
        ({"expires_at_ms": 61_001}, "validity"),
        ({"intent_envelope_digest": _hash("wrong-envelope")}, "does not bind"),
    ),
)
def test_solver_input_binds_signed_envelope_and_time(mutation: dict, message: str) -> None:
    request = _request() | mutation
    with pytest.raises(PluginSchemaError, match=message):
        validate_intent_solver_input(request)


def test_solver_input_rejects_noncanonical_or_signature_tampered_envelope() -> None:
    request = _request()
    envelope = json.loads(request["intent_envelope_json"])
    noncanonical = deepcopy(request)
    noncanonical["intent_envelope_json"] = json.dumps(envelope, ensure_ascii=False)
    with pytest.raises(PluginSchemaError, match="canonical JSON"):
        validate_intent_solver_input(noncanonical)

    envelope["scope_id"] = "workspace:tampered"
    tampered = deepcopy(request)
    tampered["intent_envelope_json"] = canonical_json(envelope).decode()
    with pytest.raises(PluginSchemaError, match="valid signed IntentEnvelope"):
        validate_intent_solver_input(tampered)


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"provenance": "solver-observed", "verification_status": "content-verified"}, "conflict"),
        ({"provenance": "accepted-envelope", "source_kind": "artifact"}, "conflict"),
        ({"source_kind": "accepted-intent"}, "envelope-bound"),
    ),
)
def test_solver_input_rejects_evidence_provenance_smuggling(updates: dict, message: str) -> None:
    request = _request()
    request["evidence"][0].update(updates)
    with pytest.raises(PluginSchemaError, match=message):
        validate_intent_solver_input(request)


def test_solver_input_rejects_future_or_multiline_evidence_provenance() -> None:
    future = _request()
    future["evidence"][0]["observed_at_ms"] = future["proposed_at_ms"] + 1
    with pytest.raises(PluginSchemaError, match="after proposed_at_ms"):
        validate_intent_solver_input(future)

    multiline = _request()
    multiline["evidence"][0]["source_ref"] = "artifact:alpha\nforged"
    with pytest.raises(PluginSchemaError, match="control characters"):
        validate_intent_solver_input(multiline)


def test_solver_input_requires_digest_bound_materialized_evidence() -> None:
    tampered = _request()
    tampered["evidence"][0]["content_base64"] = base64.b64encode(
        b"different content"
    ).decode("ascii")
    with pytest.raises(PluginSchemaError, match="does not bind materialized content"):
        validate_intent_solver_input(tampered)

    oversized = _request()
    content = b"x" * 131_073
    oversized["evidence"][0].update(
        {
            "content_base64": base64.b64encode(content).decode("ascii"),
            "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
        }
    )
    with pytest.raises(PluginSchemaError, match="evidence byte limit"):
        validate_intent_solver_input(oversized)


def test_solver_proposal_rejects_authority_and_unknown_evidence() -> None:
    provider = ReviewIntentSolverProvider()
    request = _request()
    response = provider.invoke(request, _context(request))
    proposal = json.loads(response["proposal_json"])

    for field, replacement in (
        ("executable", True),
        ("commit_authority", True),
        ("review_required", False),
        ("selection_required", False),
    ):
        with pytest.raises(PluginSchemaError):
            validate_solver_proposal(proposal | {field: replacement})

    unknown = deepcopy(proposal)
    unknown["facts"][0]["evidence_digests"] = [_hash("unknown-evidence")]
    with pytest.raises(PluginSchemaError, match="unknown evidence"):
        validate_solver_proposal(unknown)

    future = deepcopy(proposal)
    future["evidence"][0]["observed_at_ms"] = proposal["created_at_ms"] + 1
    with pytest.raises(PluginSchemaError, match="after creation"):
        validate_solver_proposal(future)

    low_order = proposal | {
        "solver_did": encode_ed25519_did_key(b"\x01" + bytes(31)),
    }
    with pytest.raises(PluginSchemaError, match="canonical"):
        validate_solver_proposal(low_order)


def test_solver_exchange_rejects_permission_or_evidence_expansion() -> None:
    provider = ReviewIntentSolverProvider()
    request = _request()
    response = dict(provider.invoke(request, _context(request)))
    proposal = json.loads(response["proposal_json"])

    proposal["requested_permissions"] = ["payment.commit"]
    proposal_json = canonical_json(proposal).decode()
    expanded = response | {
        "proposal_json": proposal_json,
        "proposal_sha256": solver_proposal_digest(proposal_json),
    }
    validate_intent_solver_output(expanded)
    with pytest.raises(PluginSchemaError, match="permissions exceed"):
        validate_intent_solver_exchange(request, expanded)

    proposal = json.loads(response["proposal_json"])
    proposal["evidence"] = [
        item for item in proposal["evidence"] if item["digest"] != _evidence()["digest"]
    ]
    proposal_json = canonical_json(proposal).decode()
    removed = response | {
        "proposal_json": proposal_json,
        "proposal_sha256": solver_proposal_digest(proposal_json),
    }
    validate_intent_solver_output(removed)
    with pytest.raises(PluginSchemaError, match="preserve invocation materialized evidence"):
        validate_intent_solver_exchange(request, removed)

    unsupported = response | {
        "supported_solver_classes": ["org.nth-dao.solver.other"],
    }
    validate_intent_solver_output(unsupported)
    with pytest.raises(PluginSchemaError, match="does not support"):
        validate_intent_solver_exchange(request, unsupported)


def test_solver_context_rejects_cross_plugin_or_principal_replay() -> None:
    provider = ReviewIntentSolverProvider()
    request = _request()
    context = _context(request)
    response = provider.invoke(request, context)
    context_document = provider._context_document(context)

    for field, value in (
        ("principal", "workspace:other"),
        ("plugin_id", "org.nth-dao.intent.other-solver"),
        ("invocation_id", "fedcba9876543210fedcba9876543210"),
    ):
        changed = context_document | {field: value}
        with pytest.raises(PluginSchemaError, match="does not bind|plugin context"):
            validate_intent_solver_context_binding(response, changed)


def test_solver_context_digest_binds_acceptance_and_resources() -> None:
    request = _request()
    context = ReviewIntentSolverProvider._context_document(_context(request))
    baseline = intent_solver_invocation_context_digest(context)

    changed_audit = context | {"mandate_digest": _hash("other-audit")}
    changed_resources = context | {"resource_ids": sorted([*context["resource_ids"], _hash("extra")])}
    assert intent_solver_invocation_context_digest(changed_audit) != baseline
    assert intent_solver_invocation_context_digest(changed_resources) != baseline


def test_review_solver_rejects_permissions_and_revokes_on_disable(tmp_path: Path) -> None:
    request = _request()
    direct = ReviewIntentSolverProvider()
    with pytest.raises(PluginSchemaError, match="must be an object"):
        direct.invoke([], _context(request))  # type: ignore[arg-type]
    with pytest.raises(PluginInvocationError, match="accepts no permissions"):
        direct.invoke(
            request,
            replace(_context(request), granted_permissions=frozenset({"network.client"})),
        )
    direct.deactivate()
    with pytest.raises(PluginInvocationError, match="inactive"):
        direct.invoke(request, _context(request))

    host, item, binding = _enabled_binding(tmp_path)
    host.disable(item.plugin_id)
    with pytest.raises(PluginInvocationError, match="disabled or stale"):
        host.invoke(binding, request, authority=_authority(request))


def test_review_solver_disable_waits_for_inflight_call_and_revokes_new_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    original = ReviewIntentSolverProvider._propose

    def delayed(cls, payload, context, context_digest, *, envelope):
        entered.set()
        if not release.wait(5):
            raise RuntimeError("test release timed out")
        return original(
            payload,
            context,
            context_digest,
            envelope=envelope,
        )

    monkeypatch.setattr(ReviewIntentSolverProvider, "_propose", classmethod(delayed))
    host, item, binding = _enabled_binding(tmp_path)
    request = _request()
    with ThreadPoolExecutor(max_workers=2) as pool:
        running = pool.submit(host.invoke, binding, request, authority=_authority(request))
        assert entered.wait(2)
        stopping = pool.submit(host.disable, item.plugin_id)
        deadline = time.monotonic() + 2
        while host.resolve(INTENT_SOLVER_CAPABILITY_ID) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert host.resolve(INTENT_SOLVER_CAPABILITY_ID) == ()
        with pytest.raises(PluginInvocationError, match="disabled or stale"):
            host.invoke(binding, {"operation": "probe"}, authority=_authority())
        release.set()
        assert running.result(timeout=5)["status"] == "proposal"
        stopping.result(timeout=5)


@pytest.mark.parametrize(
    "dependency",
    (
        "canonical_json.py",
        "did_key.py",
        "host.py",
        "intent_envelope.py",
        "intent_solver.py",
        "schema.py",
    ),
)
def test_review_solver_artifact_digest_binds_security_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    dependency: str,
) -> None:
    import nth_dao.plugins.builtin.review_intent_solver as module

    original = module._reviewed_artifact_digest()
    original_read = Path.read_bytes

    def altered(path: Path) -> bytes:
        content = original_read(path)
        return content + b"\n#audit-change\n" if path.name == dependency else content

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert module._reviewed_artifact_digest() != original
