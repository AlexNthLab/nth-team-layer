"""v0.9.4 — Run the conformance vectors against the Python reference impl.

A non-Python port that wants wire compatibility must produce zero failures
under their own equivalent of `run_all_vectors()`. The Python reference
implementation MUST pass its own vectors; otherwise the file is wrong.
"""

import pytest

from nth_dao.conformance import (
    load_vectors,
    run_all_vectors,
)


def test_vectors_file_loads():
    data = load_vectors()
    assert data["format"] == "nth-dao-conformance-v1"
    assert data["schema_version"] >= 1
    assert "vectors" in data
    assert len(data["vectors"]) >= 6


def test_python_reference_passes_all_vectors():
    """The Python implementation MUST pass its own conformance vectors."""
    failures = run_all_vectors()
    if failures:
        msg_lines = ["The Python reference fails its own vectors:"]
        for f in failures:
            msg_lines.append(
                f"  [{f.category}] {f.vector_id}  expected={f.expected!r}  actual={f.actual!r}"
            )
        pytest.fail("\n".join(msg_lines))


def test_each_category_has_at_least_one_vector():
    """Every documented category MUST ship at least one vector."""
    expected_categories = {
        "canonical_json",
        "fingerprint",
        "endorsement_canonical_payload",
        "template_canonical_payload",
        "channel_message_canonical",
        "invitation_canonical",
        "team_config_canonical",
        "did_key_encoding",
        "lan_psk_tag",
        "replay_window",
        "handoff_response_v2",
        "handoff_review_packet_v1",
        "trade_offer_announcement_v1",
        "trade_offer_head_proof_v1",
        "delivery_envelope_v1",
        "delivery_ack_v1",
    }
    data = load_vectors()
    present = set(data["vectors"].keys())
    missing = expected_categories - present
    assert not missing, f"missing categories: {missing}"


def test_main_regenerator_preserves_documented_categories(tmp_path):
    """The top-level regenerator must not drop categories added by sub-generators."""
    from nth_dao.conformance.regenerate import regenerate

    out = tmp_path / "vectors.json"
    regenerate(out)
    data = load_vectors(out)
    present = set(data["vectors"].keys())
    assert {
        "mandate_intent_canonical",
        "mandate_cart_canonical",
        "mandate_payment_canonical",
        "mandate_negative_binding",
        "mandate_negative_expiry",
        "handoff_response_v2",
        "handoff_review_packet_v1",
        "trade_offer_announcement_v1",
        "trade_offer_head_proof_v1",
        "delivery_envelope_v1",
        "delivery_ack_v1",
    } <= present


def test_delivery_ack_vectors_cover_binding_time_and_version_failures():
    cases = load_vectors()["vectors"].get("delivery_ack_v1", [])
    assert len(cases) == 4
    assert cases[0]["expected_valid"] is True
    assert all(case["expected_valid"] is False for case in cases[1:])


def test_main_regenerator_matches_shipped_vectors_byte_for_byte(tmp_path):
    """Full regeneration must be deterministic and audit-friendly."""
    from nth_dao.conformance.regenerate import regenerate
    from nth_dao.conformance.runner import VECTORS_PATH

    out = tmp_path / "vectors.json"
    regenerate(out)
    assert out.read_bytes() == VECTORS_PATH.read_bytes()


def test_canonical_json_has_unicode_vector():
    """Cross-implementation unicode handling is critical; ensure coverage."""
    data = load_vectors()
    canon = data["vectors"].get("canonical_json", [])
    has_unicode = any("王" in str(v.get("input", {})) for v in canon)
    assert has_unicode, "no canonical_json vector tests unicode handling"


def test_replay_window_covers_both_boundaries():
    """Both past (replay) and future (skew) cases must be covered."""
    data = load_vectors()
    cases = data["vectors"].get("replay_window", [])
    has_past_reject = any(
        v["offset_seconds"] < -600 and not v["expected_within_window"]
        for v in cases
    )
    has_future_reject = any(
        v["offset_seconds"] > 60 and not v["expected_within_window"]
        for v in cases
    )
    assert has_past_reject, "no vector rejects ancient (replay) message"
    assert has_future_reject, "no vector rejects too-future (skew) message"


def test_handoff_response_v2_vector_pins_receipt_binding():
    """The handoff response v2 vector must pin both signature and receipt bytes."""
    data = load_vectors()
    cases = data["vectors"].get("handoff_response_v2", [])
    assert len(cases) == 1
    v = cases[0]
    stmt = v["statement"]
    assert stmt["kind"] == "nth-handoff-response-v2"
    assert stmt["response_type"] == "superseded"
    assert stmt["receipt_id"]
    assert len(stmt["receipt_content_hash"]) == 64
    entry = v["receipt_timeline_entry"]
    assert entry["type"] == "nth.handoff_response"
    payload = entry["payload"]
    assert payload["target_capsule_hash"] == stmt["target_capsule_hash"]
    assert payload["replacement_capsule_hash"] == stmt["replacement_capsule_hash"]


def test_handoff_response_v2_vector_matches_generator():
    """The shipped vector must match the deterministic generator."""
    from nth_dao.conformance.regenerate import gen_handoff_response_v2

    data = load_vectors()
    assert data["vectors"]["handoff_response_v2"] == gen_handoff_response_v2()


def test_handoff_review_packet_v1_vector_is_explicitly_not_truth():
    """Review packet vectors must not blur projection data into facts."""
    data = load_vectors()
    cases = data["vectors"].get("handoff_review_packet_v1", [])
    assert len(cases) == 1
    v = cases[0]
    packet = v["packet"]
    assert packet["packet_kind"] == "nth-handoff-review-packet-v1"
    assert packet["packet_version"] == 1
    assert packet["packet_is_signed"] is False
    assert packet["is_truth_verdict"] is False
    assert packet["evidence_summary"] == v["expected_evidence_summary"]
    assert packet["evidence_summary"]["total"] == len(packet["evidence_verification"])
    assert "claim, not a verified fact" in packet["warning"]


def test_handoff_review_packet_v1_vector_matches_generator():
    """The shipped review packet vector must match the deterministic generator."""
    from nth_dao.conformance.regenerate import gen_handoff_review_packet_v1

    data = load_vectors()
    assert data["vectors"]["handoff_review_packet_v1"] == gen_handoff_review_packet_v1()


def test_trade_offer_announcement_v1_vector_matches_generator():
    from nth_dao.conformance.regenerate import gen_trade_offer_announcement_v1

    data = load_vectors()
    assert data["vectors"]["trade_offer_announcement_v1"] == (
        gen_trade_offer_announcement_v1()
    )


def test_trade_offer_announcement_v1_vectors_cover_binding_rejections():
    data = load_vectors()
    cases = data["vectors"]["trade_offer_announcement_v1"]
    assert sum(case["expected_valid"] is True for case in cases) == 1
    rejected = [case for case in cases if case["expected_valid"] is False]
    assert len(rejected) >= 5
    assert all(case["expected_reason"] != "ok" for case in rejected)
    assert {
        "title",
        "offer_digest",
        "revision",
        "lifetime",
        "publisher_did",
    } <= {
        token
        for case in rejected
        for token in case["expected_reason"].split()
    }


def test_trade_offer_announcement_v1_runner_checks_rejection_reason():
    data = load_vectors()
    vectors = data["vectors"]["trade_offer_announcement_v1"]
    negative = next(case for case in vectors if not case["expected_valid"])
    changed = {
        **data,
        "vectors": {
            **data["vectors"],
            "trade_offer_announcement_v1": [
                {**negative, "expected_reason": "wrong expected reason"}
            ],
        },
    }
    failures = run_all_vectors(changed)
    assert len(failures) == 1
    assert failures[0].category == "trade_offer_announcement_v1"
    assert failures[0].description == "binding"


def test_trade_offer_head_proof_v1_vector_matches_generator():
    from nth_dao.conformance.regenerate import gen_trade_offer_head_proof_v1

    data = load_vectors()
    assert data["vectors"]["trade_offer_head_proof_v1"] == (
        gen_trade_offer_head_proof_v1()
    )


def test_trade_offer_head_proof_v1_covers_chain_and_freshness_rejections():
    data = load_vectors()
    cases = data["vectors"]["trade_offer_head_proof_v1"]
    assert sum(case["expected_valid"] is True for case in cases) == 1
    rejected_ids = {
        case["id"] for case in cases if case["expected_valid"] is False
    }
    assert {
        "trade-offer-head-proof-v1-missing-genesis",
        "trade-offer-head-proof-v1-reordered",
        "trade-offer-head-proof-v1-wrong-head",
        "trade-offer-head-proof-v1-expired",
    } <= rejected_ids


def test_trade_offer_head_proof_v1_runner_checks_rejection_reason():
    data = load_vectors()
    vectors = data["vectors"]["trade_offer_head_proof_v1"]
    negative = next(case for case in vectors if not case["expected_valid"])
    changed = {
        **data,
        "vectors": {
            **data["vectors"],
            "trade_offer_head_proof_v1": [
                {**negative, "expected_reason": "wrong expected reason"}
            ],
        },
    }
    failures = run_all_vectors(changed)
    assert len(failures) == 1
    assert failures[0].category == "trade_offer_head_proof_v1"
    assert failures[0].description == "validation result"
