"""Regenerate conformance vectors.json from the reference implementation.

Run with:

    python -m nth_dao.conformance.regenerate

This OVERWRITES vectors.json. The file is part of the wire-format
contract — only regenerate when you've explicitly changed the spec.
A PR that touches vectors.json without rationale should be rejected.

Vectors use FIXED keys (not random) so other-language implementations
can reproduce the exact same outputs from the same inputs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from ..identity import canonical_json
from ._gen_mandate_vectors import build_mandate_vectors
from .runner import VECTORS_PATH


VECTOR_GENERATED_AT = "2026-08-02T00:00:00"


# ─────────────────── fixed test keys ───────────────────
# These are NOT real keys for any production agent. They are deterministic
# test fixtures so any implementation can reproduce.

ALICE_SEED_HEX = "00" * 31 + "01"  # 32 bytes
BOB_SEED_HEX   = "00" * 31 + "02"
CAROL_SEED_HEX = "00" * 31 + "03"


def _seed_keypair(seed_hex: str) -> dict:
    """Derive Ed25519 keypair from a deterministic seed."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        return {"private_hex": seed_hex, "pubkey_hex": "00" * 32}
    sk = SigningKey(bytes.fromhex(seed_hex))
    pk = sk.verify_key
    return {
        "private_hex": seed_hex,
        "pubkey_hex": pk.encode().hex(),
    }


# ─────────────────── individual generators ───────────────────


def gen_canonical_json() -> list:
    """Verify the canonical JSON encoder is byte-identical across implementations."""
    cases: list[Dict[str, Any]] = [
        {
            "id": "canon-001",
            "description": "Empty object",
            "input": {},
        },
        {
            "id": "canon-002",
            "description": "Single ASCII field",
            "input": {"name": "alice"},
        },
        {
            "id": "canon-003",
            "description": "Field order MUST be sorted alphabetically",
            "input": {"z": 1, "a": 2, "m": 3},
        },
        {
            "id": "canon-004",
            "description": "Nested objects also sort keys",
            "input": {"outer": {"z": 1, "a": 2}, "another": True},
        },
        {
            "id": "canon-005",
            "description": "Arrays preserve order",
            "input": {"items": [3, 1, 2]},
        },
        {
            "id": "canon-006",
            "description": "Unicode preserved as UTF-8 (no \\u escapes)",
            "input": {"name": "Alice 王"},
        },
        {
            "id": "canon-007",
            "description": "No whitespace between tokens",
            "input": {"a": 1, "b": [2, 3]},
        },
        {
            "id": "canon-008",
            "description": "Booleans and null encoded as JSON literals",
            "input": {"yes": True, "no": False, "absent": None},
        },
    ]
    for c in cases:
        c["expected_bytes_hex"] = canonical_json(c["input"]).hex()
    return cases


def gen_fingerprint() -> list:
    """SHA-256(pubkey_hex)[:16] is the fingerprint of cryptographic agent_ids."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    bob   = _seed_keypair(BOB_SEED_HEX)
    cases: list[Dict[str, Any]] = [
        {
            "id": "fp-001",
            "description": "Fingerprint of a known Ed25519 pubkey",
            "input": {"pubkey_hex": alice["pubkey_hex"], "agent_id": ""},
        },
        {
            "id": "fp-002",
            "description": "Different pubkey → different fingerprint",
            "input": {"pubkey_hex": bob["pubkey_hex"], "agent_id": ""},
        },
        {
            "id": "fp-003",
            "description": "Plain agent_id fingerprint (no pubkey)",
            "input": {"pubkey_hex": "", "agent_id": "alice"},
        },
    ]
    for c in cases:
        inputs = c["input"]
        assert isinstance(inputs, dict)
        payload = inputs["pubkey_hex"] or inputs["agent_id"]
        c["expected_fingerprint"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return cases


def gen_signature_verify() -> list:
    """Ed25519 verify with a known message produces a stable signature."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        return []
    alice_sk = SigningKey(bytes.fromhex(ALICE_SEED_HEX))
    alice_pk = alice_sk.verify_key.encode().hex()
    msg = b"NTH DAO conformance test message"
    sig = alice_sk.sign(msg).signature.hex()
    bob = _seed_keypair(BOB_SEED_HEX)
    return [
        {
            "id": "sig-001",
            "description": "Valid signature under matching pubkey",
            "pubkey_hex": alice_pk,
            "message_hex": msg.hex(),
            "signature_hex": sig,
            "expected_valid": True,
        },
        {
            "id": "sig-002",
            "description": "Same signature under different pubkey → invalid",
            "pubkey_hex": bob["pubkey_hex"],
            "message_hex": msg.hex(),
            "signature_hex": sig,
            "expected_valid": False,
        },
        {
            "id": "sig-003",
            "description": "Tampered signature byte → invalid",
            "pubkey_hex": alice_pk,
            "message_hex": msg.hex(),
            "signature_hex": "00" + sig[2:],   # flip first byte
            "expected_valid": False,
        },
    ]


def gen_endorsement_canonical_payload() -> list:
    """Endorsement.signable_dict() canonical bytes are stable."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    bob = _seed_keypair(BOB_SEED_HEX)
    cases = [
        {
            "id": "endorse-001",
            "description": "Minimal endorsement",
            "input": {
                "endorser_pubkey":  alice["pubkey_hex"],
                "subject_pubkey":   bob["pubkey_hex"],
                "subject_agent_id": "bob",
                "depth_allowed":    1,
                "context":          "general",
                "issued_at":        "2026-01-01T00:00:00",
                "expires_at":       "2026-12-31T00:00:00",
                "sig":              "",   # signable_dict drops this
            },
        },
        {
            "id": "endorse-002",
            "description": "Endorsement with context=code_review and depth=2",
            "input": {
                "endorser_pubkey":  alice["pubkey_hex"],
                "subject_pubkey":   bob["pubkey_hex"],
                "subject_agent_id": "bob",
                "depth_allowed":    2,
                "context":          "code_review",
                "issued_at":        "2026-02-15T10:30:00",
                "expires_at":       "2026-08-15T10:30:00",
                "sig":              "",
            },
        },
    ]
    from ..web_of_trust import Endorsement
    for c in cases:
        e = Endorsement.from_dict(c["input"])
        c["expected_canonical_hex"] = canonical_json(e.signable_dict()).hex()
    return cases


def gen_template_canonical_payload() -> list:
    """MissionTemplate.signable_dict() canonical bytes are stable."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    from ..did_key import encode_ed25519_did_key_hex
    case = {
        "id": "template-001",
        "description": "Minimal v1.0.0 template",
        "input": {
            "template_id":        "code-review",
            "version":            "1.0.0",
            "publisher_pubkey":   alice["pubkey_hex"],
            "publisher_did":      encode_ed25519_did_key_hex(alice["pubkey_hex"]),
            "name":               "Code Review",
            "description":        "Review a diff.",
            "template_type":      "agent_task",
            "category":           "code_review",
            "tags":               ["python"],
            "required_capabilities": ["code_review"],
            "inputs": {},
            "outputs": {},
            "steps": [],
            "suggested_reward":   5.0,
            "suggested_deadline_hours": 0.0,
            "created_at":         "2026-01-01T00:00:00",
            "deprecated":         False,
            "deprecated_reason":  "",
            "supersedes":         [],
            "delegations":        [],
            "credentials_required": [],
            "legal_jurisdiction": "",
            "publisher_sig":      "",
        },
    }
    from ..orchestration.template import MissionTemplate
    t = MissionTemplate.from_dict(case["input"])
    case["expected_canonical_hex"] = canonical_json(t.signable_dict()).hex()
    return [case]


def gen_channel_message_canonical() -> list:
    """ChannelMessage canonical payload bytes for the sign-over-payload step."""
    # We re-create the payload exactly as TeamChannel.send() does:
    # {msg_id, channel, from_agent, content, content_type, reply_to,
    #  mentions, timestamp, metadata}
    case = {
        "id": "chmsg-001",
        "description": "Plain text ChannelMessage signable payload (no mentions / no reply)",
        "input": {
            "msg_id":       "abcd1234567890ef",
            "channel":      "team",
            "from_agent":   "alice",
            "content":      "Hello DAO",
            "content_type": "text",
            "reply_to":     "",
            "mentions":     [],
            "timestamp":    "2026-04-01T12:00:00",
            "metadata":     {},
        },
    }
    from ..identity import canonical_json
    case["expected_canonical_hex"] = canonical_json(case["input"]).hex()
    case2 = {
        "id": "chmsg-002",
        "description": "ChannelMessage with reply_to and mentions",
        "input": {
            "msg_id":       "1234567890abcdef",
            "channel":      "group:backend",
            "from_agent":   "bob",
            "content":      "ack @alice",
            "content_type": "text",
            "reply_to":     "abcd1234567890ef",
            "mentions":     ["alice"],
            "timestamp":    "2026-04-01T12:00:30",
            "metadata":     {"thread": "code-review"},
        },
    }
    case2["expected_canonical_hex"] = canonical_json(case2["input"]).hex()
    return [case, case2]


def gen_invitation_canonical() -> list:
    """Invitation.signable_dict() canonical bytes."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    case = {
        "id": "invite-001",
        "description": "Invitation minimal example",
        "input": {
            "team_id":      "t1",
            "team_name":    "Test Team",
            "owner_pubkey": alice["pubkey_hex"],
            "issuer":       "alice",
            "issued_at":    "2026-01-01T00:00:00",
            "expires_at":   "2026-01-08T00:00:00",
            "join_token":   "secret",
            "ws_url":       "ws://192.168.1.5:9876",
            "psk":          "lan-secret",
            "sig":          "",
        },
    }
    from ..invitation import Invitation
    inv = Invitation.from_dict(case["input"])
    case["expected_canonical_hex"] = canonical_json(inv.signable_dict()).hex()
    return [case]


def gen_team_config_canonical() -> list:
    """TeamConfig.signable_dict() canonical bytes for owner-signed configs."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    case = {
        "id": "team-001",
        "description": "Signed TeamConfig minimal example",
        "input": {
            "team_id":        "abc12345",
            "team_name":      "Test Team",
            "join_policy":    "approval",
            "join_token":     "",
            "admin_ids":      ["alice"],
            "member_ids":     ["alice"],
            "roles":          {"alice": "owner"},
            "created_at":     "2026-01-01T00:00:00",
            "metadata":       {},
            "owner_pubkey":   alice["pubkey_hex"],
            "owner_sig":      "",
            "sig_updated_at": "2026-01-01T00:00:00",
        },
    }
    from ..membership import TeamConfig
    cfg = TeamConfig.from_dict(case["input"])
    case["expected_canonical_hex"] = canonical_json(cfg.signable_dict()).hex()
    return [case]


def gen_did_key_encoding() -> list:
    """did:key encoding/decoding of Ed25519 pubkeys.

    Lets a non-Python implementation verify their base58btc + multicodec
    handling against deterministic test pubkeys.
    """
    from ..did_key import encode_ed25519_did_key_hex
    cases = []
    for label, hex_pk in (
        ("did-001", "00" * 32),
        ("did-002", "01" * 32),
        ("did-003", "".join(f"{i:02x}" for i in range(32))),
    ):
        cases.append({
            "id": label,
            "description": f"Encode pubkey {hex_pk[:8]}... as did:key",
            "input": {"pubkey_hex": hex_pk},
            "expected_did": encode_ed25519_did_key_hex(hex_pk),
        })
    return cases


def gen_lan_psk_tag() -> list:
    """LAN discovery psk_tag = HMAC-SHA256(psk, canonical_json(message - psk_tag)).

    Lock the construction so a Go/Rust port produces byte-identical tags.
    """
    import hashlib
    import hmac as _hmac
    import json as _json
    cases = []
    for cid, psk, msg in (
        ("psk-001", "team-secret", {"type": "nth-dao-query", "v": 1,
                                     "from": "alice", "wants": [],
                                     "nonce": "deadbeef"}),
        ("psk-002", "team-secret", {"type": "nth-dao-hello", "v": 1,
                                     "agent_id": "alice",
                                     "nonce": "feedface"}),
    ):
        canon = _json.dumps(
            {k: v for k, v in msg.items() if k != "psk_tag"},
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        tag = _hmac.new(psk.encode("utf-8"), canon, hashlib.sha256).hexdigest()
        cases.append({
            "id": cid,
            "description": f"HMAC-SHA256 psk_tag over canonical {msg.get('type')}",
            "input": {"psk": psk, "message": msg},
            "expected_psk_tag": tag,
        })
    return cases


def gen_replay_window() -> list:
    """Replay window boundaries.

    Offsets are relative to "now" at runtime — vectors stay valid regardless
    of when the conformance suite runs.
    """
    return [
        {
            "id": "replay-001",
            "description": "Message timestamp = now → accepted",
            "offset_seconds": 0,
            "expected_within_window": True,
        },
        {
            "id": "replay-002",
            "description": "Message timestamp = 30 seconds ago → accepted",
            "offset_seconds": -30,
            "expected_within_window": True,
        },
        {
            "id": "replay-003",
            "description": "Message timestamp = 30 seconds in future (allowed clock skew) → accepted",
            "offset_seconds": 30,
            "expected_within_window": True,
        },
        {
            "id": "replay-004",
            "description": "Message timestamp = 120 seconds in future → REJECTED (drift cap)",
            "offset_seconds": 120,
            "expected_within_window": False,
        },
        {
            "id": "replay-005",
            "description": "Message timestamp = 700 seconds ago → REJECTED (replay window)",
            "offset_seconds": -700,
            "expected_within_window": False,
        },
    ]


# ─────────────────── top-level ───────────────────


def gen_handoff_response_v2() -> list:
    """Signed handoff response v2 and its receipt-binding timeline entry."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        return []

    from ..identity import AgentID, AgentIdentity
    from ..runtime import sign_handoff_response

    alice_sk = SigningKey(bytes.fromhex(ALICE_SEED_HEX))
    alice_pk = alice_sk.verify_key.encode()
    alice = AgentIdentity(
        agent_id=AgentID.from_pubkey(alice_pk.hex()),
        label="Alice",
        _signing_key=bytes.fromhex(ALICE_SEED_HEX),
        _verify_key=alice_pk,
    )
    stmt = sign_handoff_response(
        signer=alice,
        response_type="superseded",
        target_capsule_hash="sha256:" + "1" * 64,
        replacement_capsule_hash="sha256:" + "2" * 64,
        mission_id="mission-conformance-1",
        reason=(
            "Replacement capsule corrects the prior claim after re-checking "
            "pinned evidence."
        ),
        counter_evidence=[{
            "kind": "source_span",
            "commit": "a" * 40,
            "path": "nth_dao/runtime/handoff.py",
            "symbol": "record_handoff_response_checked",
            "content_hash": "sha256:" + "3" * 64,
        }],
        receipt_id="receipt-handoff-1",
        receipt_content_hash="4" * 64,
        issued_at_ms=1800000000000,
    )
    receipt_entry = {
        "timestamp": 1800000000001,
        "type": "nth.handoff_response",
        "payload": {
            "mission_id": stmt["mission_id"],
            "response_type": stmt["response_type"],
            "target_capsule_hash": stmt["target_capsule_hash"],
            "replacement_capsule_hash": stmt["replacement_capsule_hash"],
        },
    }
    return [{
        "id": "handoff-response-v2-001",
        "description": (
            "Signed v2 supersession response with receipt binding timeline entry"
        ),
        "statement": stmt,
        "expected_response_hash": stmt["response_hash"],
        "expected_signing_body_hex": canonical_json({
            k: v for k, v in stmt.items() if k != "sig"
        }).hex(),
        "receipt_timeline_entry": receipt_entry,
        "expected_receipt_timeline_entry_hex": canonical_json(receipt_entry).hex(),
        "expected_valid": True,
    }]


def gen_handoff_review_packet_v1() -> list:
    """Derived handoff review packet v1 projection.

    This vector deliberately does NOT sign the packet. The packet is a
    replay/projection helper; the signed truth claims are the handoff capsule
    and response statements that feed it.
    """
    evidence_verification = [
        {
            "kind": "source_span",
            "commit": "a" * 40,
            "path": "nth_dao/runtime/handoff.py",
            "symbol": "record_handoff_response",
            "content_hash": "sha256:" + "1" * 64,
            "status": "verified",
            "reason": "content hash matches pinned git blob",
            "source": "env:NTH_SOURCE_REPOS",
            "repo_matched_by": "repo_url",
            "commit_reachable": True,
            "blob_reachable": True,
        },
        {
            "kind": "source_span",
            "commit": "b" * 40,
            "path": "nth_dao/web/v2_api.py",
            "symbol": "_handoff_review_packet",
            "content_hash": "sha256:" + "2" * 64,
            "status": "unreachable",
            "reason": "commit not found in mapped source repository",
            "source": "env:NTH_SOURCE_REPOS",
            "repo_matched_by": "source_root",
            "commit_reachable": False,
            "blob_reachable": False,
        },
    ]
    evidence_summary = {
        "total": 2,
        "verified": 1,
        "unreachable": 1,
        "unavailable": 0,
        "mismatch": 0,
        "invalid": 0,
        "unsupported": 0,
    }
    packet = {
        "packet_kind": "nth-handoff-review-packet-v1",
        "packet_version": 1,
        "packet_is_signed": False,
        "is_truth_verdict": False,
        "warning": "Signed handoff is a claim, not a verified fact.",
        "goal": (
            "Use the least context needed to re-check, continue, or refute "
            "this handoff."
        ),
        "mission_id": "mission-conformance-1",
        "step_id": "step-review",
        "capsule_hash": "sha256:" + "3" * 64,
        "status": "proposed",
        "verification_status": "unverified",
        "author_did": "did:key:z6MkconformanceAuthor",
        "finding": "The dispatch path drops signed handoff responses.",
        "root_cause_hypothesis": (
            "The response writer did not bind receipts to target capsules."
        ),
        "evidence_summary": evidence_summary,
        "evidence_verification": evidence_verification,
        "changed_files": ["nth_dao/runtime/handoff.py"],
        "tests": ["python -m pytest tests/test_runtime_handoff.py -q"],
        "risks": ["Signature proves authorship, not correctness."],
        "next_actions": ["Re-check evidence, then refute or supersede if wrong."],
        "required_review_steps": [
            "Verify each evidence pointer against its pinned commit and content hash.",
            "Rerun or inspect the listed tests before trusting the finding.",
            "If the claim is wrong, sign a refutation or superseding handoff with a receipt.",
        ],
    }
    return [{
        "id": "handoff-review-packet-v1-001",
        "description": "Derived v1 review packet is stable and explicitly non-truth.",
        "packet": packet,
        "expected_canonical_hex": canonical_json(packet).hex(),
        "expected_evidence_summary": evidence_summary,
        "expected_packet_is_signed": False,
        "expected_is_truth_verdict": False,
    }]


def gen_trade_offer_announcement_v1() -> list:
    """Pin positive and signed-negative Offer discovery bindings."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        return []

    from ..identity import AgentID, AgentIdentity
    from ..market import (
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
        TaskAnnouncement,
        announcement_federation_key,
        create_trade_offer_announcement,
        sign_announcement,
    )
    from ..trade_rules import offer_body, sign_offer

    signing_key = SigningKey(bytes.fromhex(ALICE_SEED_HEX))
    public_key = signing_key.verify_key.encode()
    publisher = AgentIdentity(
        agent_id=AgentID.from_pubkey(public_key.hex()),
        label="conformance-publisher",
        _signing_key=signing_key.encode(),
        _verify_key=public_key,
    )
    offer = sign_offer(
        publisher,
        offer_body(
            offer_id="org.nthdao.conformance/swap",
            publisher_did=publisher.as_did(),
            title="Compute for review",
            summary="Exchange one compute task for one signed code review.",
            provides=[{
                "leg_id": "compute",
                "resource_type": "service:compute",
                "resource_id": "urn:nth:conformance:compute",
                "quantity": "1",
                "unit": "task",
                "descriptor_digest": "sha256:" + ("a" * 64),
            }],
            requests=[{
                "leg_id": "review",
                "resource_type": "service:code-review",
                "resource_id": "urn:nth:conformance:review",
                "quantity": "1",
                "unit": "review",
                "descriptor_digest": "sha256:" + ("b" * 64),
            }],
            published_at="2026-08-01T00:00:00Z",
            not_after="2026-08-02T00:00:00Z",
        ),
        created="2026-08-01T00:00:01Z",
    )
    announcement = create_trade_offer_announcement(
        publisher,
        offer,
        announcement_id="trade-offer-conformance-001",
        capability_set=["code-review", "compute"],
        availability_summary={"status": "publisher-asserted-available"},
        published_at_ms=1_785_542_402_000,
        not_after_ms=1_785_628_799_000,
    )

    def resign(
        source: TaskAnnouncement,
        *,
        signer: AgentIdentity = publisher,
        **changes: object,
    ) -> TaskAnnouncement:
        body = source.signing_body()
        body.pop("publisher_did")
        body.update(changes)
        return sign_announcement(publisher=signer, **body)

    forged_digest = "sha256:" + ("c" * 64)
    bob_signing_key = SigningKey(bytes.fromhex(BOB_SEED_HEX))
    bob_public_key = bob_signing_key.verify_key.encode()
    bob = AgentIdentity(
        agent_id=AgentID.from_pubkey(bob_public_key.hex()),
        label="conformance-non-publisher",
        _signing_key=bob_signing_key.encode(),
        _verify_key=bob_public_key,
    )
    negative_cases = [
        (
            "trade-offer-announcement-v1-title-mismatch",
            "A valid signature cannot authorize a title that differs from the Offer.",
            resign(announcement, title="Different signed title"),
            "Trade Offer announcement binding mismatch: title",
        ),
        (
            "trade-offer-announcement-v1-digest-mismatch",
            "A self-consistent digest and URI pair must still bind the supplied Offer.",
            resign(
                announcement,
                offer_digest=forged_digest,
                offer_uri=(
                    "/api/v2/trade/federation/offers/" + forged_digest
                ),
            ),
            "Trade Offer announcement binding mismatch: offer_digest",
        ),
        (
            "trade-offer-announcement-v1-revision-mismatch",
            "The signed availability summary must bind the Offer revision.",
            resign(
                announcement,
                availability_summary={
                    **announcement.availability_summary,
                    "revision": announcement.availability_summary["revision"] + 1,
                },
            ),
            "availability summary does not bind revision",
        ),
        (
            "trade-offer-announcement-v1-expiry-outlives-offer",
            "An announcement must not remain live after its Offer expires.",
            resign(announcement, not_after=1_785_628_801_000),
            "announcement expiry is outside the Trade Offer lifetime",
        ),
        (
            "trade-offer-announcement-v1-publisher-mismatch",
            "A valid signature by another DID cannot publish this Offer.",
            resign(announcement, signer=bob, authority_did=bob.as_did()),
            "Trade Offer announcement binding mismatch: publisher_did",
        ),
    ]

    def vector(
        *,
        vector_id: str,
        description: str,
        signed_announcement: TaskAnnouncement,
        expected_valid: bool,
        expected_reason: str,
    ) -> dict:
        assert signed_announcement.kind == (
            NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1
        )
        return {
            "id": vector_id,
            "description": description,
            "offer": offer.to_dict(),
            "announcement": signed_announcement.to_dict(),
            "expected_valid": expected_valid,
            "expected_reason": expected_reason,
            "expected_signing_body_hex": canonical_json(
                signed_announcement.signing_body()
            ).hex(),
            "expected_federation_key": announcement_federation_key(
                signed_announcement
            ),
        }

    vectors = [
        vector(
            vector_id="trade-offer-announcement-v1-valid",
            description=(
                "Signed exchange discovery hint binds one exact signed Trade Offer."
            ),
            signed_announcement=announcement,
            expected_valid=True,
            expected_reason="ok",
        )
    ]
    vectors.extend(
        vector(
            vector_id=vector_id,
            description=description,
            signed_announcement=signed_announcement,
            expected_valid=False,
            expected_reason=expected_reason,
        )
        for vector_id, description, signed_announcement, expected_reason
        in negative_cases
    )
    return vectors


def gen_trade_offer_head_proof_v1() -> list:
    """Pin complete signed revision-chain validation and rejection behavior."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        return []

    from ..identity import AgentID, AgentIdentity
    from ..market import (
        TRADE_OFFER_HEAD_PROOF_KIND_V1,
        create_trade_offer_announcement,
    )
    from ..trade_rules import offer_body, sign_offer

    signing_key = SigningKey(bytes.fromhex(ALICE_SEED_HEX))
    public_key = signing_key.verify_key.encode()
    publisher = AgentIdentity(
        agent_id=AgentID.from_pubkey(public_key.hex()),
        label="conformance-publisher",
        _signing_key=signing_key.encode(),
        _verify_key=public_key,
    )
    first = sign_offer(
        publisher,
        offer_body(
            offer_id="org.nthdao.conformance/head-proof",
            publisher_did=publisher.as_did(),
            title="Compute for review",
            summary="Exchange one compute task for one signed code review.",
            provides=[{
                "leg_id": "compute",
                "resource_type": "service:compute",
                "resource_id": "urn:nth:conformance:compute",
                "quantity": "1",
                "unit": "task",
                "descriptor_digest": "sha256:" + ("a" * 64),
            }],
            requests=[{
                "leg_id": "review",
                "resource_type": "service:code-review",
                "resource_id": "urn:nth:conformance:review",
                "quantity": "1",
                "unit": "review",
                "descriptor_digest": "sha256:" + ("b" * 64),
            }],
            published_at="2026-08-01T00:00:00Z",
            not_after="2026-08-02T00:00:00Z",
        ),
        created="2026-08-01T00:00:01Z",
    )
    successor_body = first.to_dict()
    successor_body.pop("proof")
    successor_body.update({
        "revision": 2,
        "previous_offer_digest": (
            "sha256:" + hashlib.sha256(first.canonical_bytes).hexdigest()
        ),
        "published_at": "2026-08-01T00:00:30Z",
    })
    second = sign_offer(
        publisher,
        successor_body,
        created="2026-08-01T00:00:31Z",
    )
    announcement = create_trade_offer_announcement(
        publisher,
        second,
        announcement_id="trade-offer-head-proof-conformance-001",
        capability_set=["code-review", "compute"],
        availability_summary={"status": "publisher-asserted-available"},
        published_at_ms=1_785_542_432_000,
        not_after_ms=1_785_628_799_000,
    )
    valid_proof = {
        "kind": TRADE_OFFER_HEAD_PROOF_KIND_V1,
        "announcement": announcement.to_dict(),
        "offers": [first.to_dict(), second.to_dict()],
    }
    verification_time_ms = 1_785_542_433_000

    def clone(value: dict) -> dict:
        return json.loads(json.dumps(value))

    missing_genesis = clone(valid_proof)
    missing_genesis["offers"] = [missing_genesis["offers"][1]]
    reordered = clone(valid_proof)
    reordered["offers"] = list(reversed(reordered["offers"]))
    wrong_head = clone(valid_proof)
    wrong_head["offers"] = [wrong_head["offers"][0]]
    cases = [
        (
            "trade-offer-head-proof-v1-valid",
            "A signed announcement binds an unbroken two-revision Offer chain.",
            valid_proof,
            verification_time_ms,
            True,
            "ok",
        ),
        (
            "trade-offer-head-proof-v1-missing-genesis",
            "A disclosed chain cannot begin at revision two.",
            missing_genesis,
            verification_time_ms,
            False,
            "Trade Offer head proof must start at revision 1 and be contiguous",
        ),
        (
            "trade-offer-head-proof-v1-reordered",
            "Signed revisions remain invalid when presented out of order.",
            reordered,
            verification_time_ms,
            False,
            "Trade Offer head proof must start at revision 1 and be contiguous",
        ),
        (
            "trade-offer-head-proof-v1-wrong-head",
            "The announcement must bind the final disclosed revision.",
            wrong_head,
            verification_time_ms,
            False,
            (
                "Trade Offer head proof announcement mismatch: "
                "Trade Offer announcement binding mismatch: offer_digest"
            ),
        ),
        (
            "trade-offer-head-proof-v1-expired",
            "A cryptographically valid but expired publisher head claim is rejected.",
            valid_proof,
            announcement.not_after + 1,
            False,
            "Trade Offer head proof announcement is expired",
        ),
    ]
    return [
        {
            "id": vector_id,
            "description": description,
            "proof": proof,
            "verification_time_ms": moment,
            "expected_valid": expected_valid,
            "expected_reason": expected_reason,
            "expected_canonical_hex": (
                canonical_json(proof).hex() if expected_valid else None
            ),
        }
        for (
            vector_id,
            description,
            proof,
            moment,
            expected_valid,
            expected_reason,
        ) in cases
    ]


def gen_delivery_envelope_v1() -> list:
    """TransportEnvelope v1: canonical bytes, content address, negatives.

    Deterministic: fixed seed key, fixed timestamps, fixed nonce. A port
    must reproduce the canonical bytes, the message_id, the wire digest,
    and the exact accept/reject reason strings.
    """
    try:
        from nacl.signing import SigningKey
    except ImportError:
        return []
    from copy import deepcopy

    from ..delivery.envelope import (
        TransportEnvelope,
        TransportEnvelopeRejected,
        envelope_digest,
        sign_envelope,
        validate_envelope,
    )
    from ..identity import AgentID, AgentIdentity

    sk = SigningKey(bytes.fromhex(ALICE_SEED_HEX))
    verify_bytes = sk.verify_key.encode()
    identity = AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_bytes.hex()),
        label="vector-alice",
        _signing_key=bytes.fromhex(ALICE_SEED_HEX),
        _verify_key=verify_bytes,
    )
    envelope = sign_envelope(
        identity,
        kind="mission.announcement",
        recipient="dao:core",
        payload={"body": "hello", "seq": 1},
        created_at_ms=1_750_000_000_000,
        expires_at_ms=1_750_000_060_000,
        hop_limit=3,
        nonce="DeliveryVectorNonce0123456789",
    )
    wire = envelope.to_dict()
    verification_time_ms = 1_750_000_001_000

    def _reason(data: dict, now_ms: int) -> tuple:
        try:
            candidate = TransportEnvelope.from_dict(data)
            return validate_envelope(candidate, now_ms=now_ms)
        except TransportEnvelopeRejected as exc:
            return (False, str(exc))

    vectors = [
        {
            "id": "delivery-envelope-001",
            "description": "Signed envelope validates; canonical bytes, message id, and wire digest are stable",
            "input": deepcopy(wire),
            "verification_time_ms": verification_time_ms,
            "expected_valid": True,
            "expected_reason": "ok",
            "expected_canonical_hex": canonical_json(wire).hex(),
            "expected_message_id": envelope.message_id,
            "expected_envelope_sha256": envelope_digest(envelope),
        },
    ]

    def _negative(vid: str, description: str, mutate, now_ms: int = verification_time_ms) -> dict:
        data = deepcopy(wire)
        mutate(data)
        ok, reason = _reason(data, now_ms)
        assert not ok, f"vector {vid} unexpectedly validates"
        return {
            "id": vid,
            "description": description,
            "input": data,
            "verification_time_ms": now_ms,
            "expected_valid": False,
            "expected_reason": reason,
        }

    def _tamper_payload(data):
        data["payload"]["body"] = "evil"

    def _tamper_signature(data):
        sig = list(data["signature"])
        sig[8] = "A" if sig[8] != "A" else "B"
        data["signature"] = "".join(sig)

    def _bump_version(data):
        data["version"] = 2

    def _add_unknown_field(data):
        data["extra"] = "nope"

    vectors.append(_negative(
        "delivery-envelope-002",
        "Tampered payload → payload hash gate rejects",
        _tamper_payload,
    ))
    vectors.append(_negative(
        "delivery-envelope-003",
        "Tampered signature byte → signature gate rejects",
        _tamper_signature,
    ))
    vectors.append(_negative(
        "delivery-envelope-004",
        "Verification after expiry → TTL gate rejects",
        lambda data: None,
        now_ms=1_750_000_060_001,
    ))
    vectors.append(_negative(
        "delivery-envelope-005",
        "Unknown protocol version → fail closed",
        _bump_version,
    ))
    vectors.append(_negative(
        "delivery-envelope-006",
        "Unknown field → fail closed",
        _add_unknown_field,
    ))
    return vectors


def gen_delivery_ack_v1() -> list:
    """DeliveryAck v1: canonical bytes, signature, binding, and negatives."""

    try:
        from nacl.signing import SigningKey
    except ImportError:
        return []
    from copy import deepcopy

    from ..delivery.acknowledgement import (
        DeliveryAck,
        ack_digest,
        sign_ack,
        validate_ack,
    )
    from ..identity import AgentID, AgentIdentity

    signing_key = SigningKey(bytes.fromhex(BOB_SEED_HEX))
    verify_bytes = signing_key.verify_key.encode()
    identity = AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_bytes.hex()),
        label="vector-bob",
        _signing_key=bytes.fromhex(BOB_SEED_HEX),
        _verify_key=verify_bytes,
    )
    ack = sign_ack(
        identity,
        message_id="sha256:" + "1" * 64,
        envelope_sha256="sha256:" + "2" * 64,
        received_at_ms=1_750_000_002_000,
    )
    wire = ack.to_dict()
    verification_time_ms = 1_750_000_003_000
    vectors = [
        {
            "id": "delivery-ack-001",
            "description": "Signed ACK validates and has stable canonical bytes",
            "input": deepcopy(wire),
            "verification_time_ms": verification_time_ms,
            "expected_valid": True,
            "expected_reason": "ok",
            "expected_canonical_hex": canonical_json(wire).hex(),
            "expected_ack_sha256": ack_digest(ack),
        }
    ]

    def _negative(vector_id: str, description: str, mutate) -> dict:
        data = deepcopy(wire)
        mutate(data)
        return {
            "id": vector_id,
            "description": description,
            "input": data,
            "verification_time_ms": verification_time_ms,
            "expected_valid": False,
            "expected_reason": validate_ack(
                DeliveryAck.from_dict(data),
                now_ms=verification_time_ms,
            )[1],
        }

    vectors.append(
        _negative(
            "delivery-ack-002",
            "Tampered envelope digest invalidates the receiver signature",
            lambda data: data.__setitem__("envelope_sha256", "sha256:" + "3" * 64),
        )
    )
    vectors.append(
        _negative(
            "delivery-ack-003",
            "A future-dated ACK outside clock skew fails closed",
            lambda data: data.__setitem__("received_at_ms", 1_750_001_000_000),
        )
    )
    vectors.append(
        _negative(
            "delivery-ack-004",
            "An unknown protocol version fails closed",
            lambda data: data.__setitem__("version", 2),
        )
    )
    return vectors


def regenerate(path: Path = VECTORS_PATH) -> None:
    vectors: Dict[str, Any] = {
        "format": "nth-dao-conformance-v1",
        "schema_version": 1,
        "generated_at": VECTOR_GENERATED_AT,
        "reference_impl": "nth-dao Python (pyproject version)",
        "vectors": {
            "canonical_json":              gen_canonical_json(),
            "fingerprint":                 gen_fingerprint(),
            "signature_verify":            gen_signature_verify(),
            "endorsement_canonical_payload": gen_endorsement_canonical_payload(),
            "template_canonical_payload":  gen_template_canonical_payload(),
            "channel_message_canonical":   gen_channel_message_canonical(),
            "invitation_canonical":        gen_invitation_canonical(),
            "team_config_canonical":       gen_team_config_canonical(),
            "did_key_encoding":            gen_did_key_encoding(),
            "lan_psk_tag":                 gen_lan_psk_tag(),
            "replay_window":               gen_replay_window(),
            **build_mandate_vectors(),
            "handoff_response_v2":         gen_handoff_response_v2(),
            "handoff_review_packet_v1":    gen_handoff_review_packet_v1(),
            "trade_offer_announcement_v1": gen_trade_offer_announcement_v1(),
            "trade_offer_head_proof_v1":   gen_trade_offer_head_proof_v1(),
            "delivery_envelope_v1":        gen_delivery_envelope_v1(),
            "delivery_ack_v1":             gen_delivery_ack_v1(),
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=2, ensure_ascii=False, sort_keys=True)
    counts = {k: len(v) for k, v in vectors["vectors"].items()}
    print(f"wrote {path}")
    print(f"  categories: {len(counts)}")
    for k, n in counts.items():
        print(f"    {k:35s} {n} vectors")


if __name__ == "__main__":
    regenerate()
