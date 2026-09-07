"""Tests for nth_dao.delivery.envelope — TransportEnvelope v1.

Covers the fail-closed wire contract: canonical bytes, content-addressed
message_id, author signature scope (mutable hop counter excluded), TTL
windows, and every negative case the integration design doc §10 requires.
"""

from __future__ import annotations

import copy
import json

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    DEFAULT_HOP_LIMIT,
    ENVELOPE_PROTOCOL,
    ENVELOPE_VERSION,
    MAX_CLOCK_SKEW_MS,
    MAX_ENVELOPE_BYTES,
    MAX_HOP_LIMIT,
    MAX_PAYLOAD_BYTES,
    MAX_TTL_MS,
    TransportEnvelope,
    TransportEnvelopeRejected,
    envelope_digest,
    forward_envelope,
    new_nonce,
    sign_envelope,
    validate_envelope,
)

pytest.importorskip("nacl")

NOW_MS = 1_750_000_000_000


@pytest.fixture()
def alice_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="alice")


def _signed(alice_identity, *, kind="mission.announcement", recipient="dao:core",
            payload=None, created_at_ms=NOW_MS, ttl_ms=60_000, **kwargs):
    return sign_envelope(
        alice_identity,
        kind=kind,
        recipient=recipient,
        payload={"body": "hello"} if payload is None else payload,
        created_at_ms=created_at_ms,
        expires_at_ms=created_at_ms + ttl_ms,
        **kwargs,
    )


# ─────────────────────── happy path ───────────────────────


class TestEnvelopeHappyPath:
    def test_signed_envelope_validates(self, alice_identity):
        envelope = _signed(alice_identity, dao_id="dao-core")
        ok, reason = validate_envelope(envelope, now_ms=NOW_MS + 1_000)
        assert ok, reason
        assert envelope.protocol == ENVELOPE_PROTOCOL
        assert envelope.version == ENVELOPE_VERSION

    def test_message_id_is_content_addressed(self, alice_identity):
        envelope = _signed(alice_identity)
        assert envelope.message_id.startswith("sha256:")
        body = dict(envelope.content_body())
        assert envelope.message_id == "sha256:" + canonical_json_sha256(body)

    def test_message_id_stable_across_resign_of_same_content(self, alice_identity):
        first = _signed(alice_identity, payload={"a": 1})
        second = sign_envelope(
            alice_identity,
            kind=first.kind,
            recipient=first.recipient,
            payload={"a": 1},
            created_at_ms=first.created_at_ms,
            expires_at_ms=first.expires_at_ms,
            nonce=first.nonce,
        )
        # same content, same nonce -> same content address, different signature OK
        assert first.message_id == second.message_id

    def test_signature_covers_sender_and_payload(self, alice_identity, bob_identity):
        envelope = _signed(alice_identity)
        body = envelope.signing_body()
        body["sender_did"] = bob_identity.as_did()
        assert not alice_identity.verify(canonical_json(body), b"", signature_bytes(envelope))
        # tampered payload breaks the signature
        tampered = replace_payload(envelope, {"body": "evil"})
        ok, reason = validate_envelope(tampered, now_ms=NOW_MS + 1_000)
        assert not ok and "signature" in reason or "hash" in reason

    def test_hop_count_is_outside_signature(self, alice_identity):
        envelope = _signed(alice_identity, hop_limit=3)
        forwarded = forward_envelope(envelope)
        assert forwarded.routing["hop_count"] == 1
        # signature and message_id unchanged by forwarding
        assert forwarded.signature == envelope.signature
        assert forwarded.message_id == envelope.message_id
        ok, reason = validate_envelope(forwarded, now_ms=NOW_MS + 1_000)
        assert ok, reason

    def test_forward_chain_up_to_limit_then_reject(self, alice_identity):
        envelope = _signed(alice_identity, hop_limit=2)
        one = forward_envelope(envelope)
        two = forward_envelope(one)
        assert two.routing["hop_count"] == 2
        with pytest.raises(TransportEnvelopeRejected, match="hop budget"):
            forward_envelope(two)

    def test_wire_roundtrip_via_canonical_json(self, alice_identity):
        envelope = _signed(alice_identity, dao_id="dao-core")
        wire = canonical_json(envelope.to_dict())
        assert len(wire) <= MAX_ENVELOPE_BYTES
        restored = TransportEnvelope.from_dict(json.loads(wire.decode()))
        ok, reason = validate_envelope(restored, now_ms=NOW_MS + 1_000)
        assert ok, reason
        assert envelope_digest(restored) == envelope_digest(envelope)

    def test_envelope_digest_binds_wire_bytes(self, alice_identity):
        envelope = _signed(alice_identity, hop_limit=2)
        forwarded = forward_envelope(envelope)
        # hop_count is on the wire, so the wire digest moves even though the
        # message_id does not — dedup keys on message_id, integrity on digest
        assert envelope_digest(forwarded) != envelope_digest(envelope)


def canonical_json_sha256(document):
    import hashlib

    return hashlib.sha256(canonical_json(document)).hexdigest()


def signature_bytes(envelope):
    from nth_dao.b64u import b64u_decode

    return b64u_decode(envelope.signature)


def replace_payload(envelope, payload):
    return TransportEnvelope(
        message_id=envelope.message_id,
        kind=envelope.kind,
        sender_did=envelope.sender_did,
        recipient=envelope.recipient,
        dao_id=envelope.dao_id,
        created_at_ms=envelope.created_at_ms,
        expires_at_ms=envelope.expires_at_ms,
        nonce=envelope.nonce,
        payload_hash=envelope.payload_hash,
        payload=payload,
        routing=dict(envelope.routing),
        signature=envelope.signature,
    )


@pytest.fixture()
def bob_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="bob")


# ─────────────────────── negative cases ───────────────────────


class TestEnvelopeNegative:
    def test_unknown_top_level_field_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        data = envelope.to_dict()
        data["extra"] = "nope"
        with pytest.raises(TransportEnvelopeRejected, match="unknown fields"):
            TransportEnvelope.from_dict(data)

    def test_missing_field_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        data = envelope.to_dict()
        del data["nonce"]
        with pytest.raises(TransportEnvelopeRejected, match="missing or unknown"):
            TransportEnvelope.from_dict(data)

    def test_wrong_protocol_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.protocol = "nth-transport-envelope-v9"
        ok, reason = validate_envelope(envelope)
        assert not ok and "protocol" in reason

    def test_unknown_version_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.version = 2
        ok, reason = validate_envelope(envelope)
        assert not ok and "version" in reason

    def test_boolean_version_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.version = True
        ok, reason = validate_envelope(envelope)
        assert not ok and "version" in reason

    def test_expired_envelope_rejected(self, alice_identity):
        envelope = _signed(alice_identity, ttl_ms=1_000)
        ok, reason = validate_envelope(envelope, now_ms=envelope.expires_at_ms + 1)
        assert not ok and "expired" in reason

    def test_future_created_beyond_skew_rejected(self, alice_identity):
        envelope = _signed(alice_identity, created_at_ms=NOW_MS + MAX_CLOCK_SKEW_MS + 1)
        ok, reason = validate_envelope(envelope, now_ms=NOW_MS)
        assert not ok and "future" in reason

    def test_ttl_over_maximum_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="TTL"):
            _signed(alice_identity, ttl_ms=MAX_TTL_MS + 1)

    def test_inverted_ttl_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="after created"):
            sign_envelope(
                alice_identity,
                kind="mission.announcement",
                recipient="dao:core",
                payload={"a": 1},
                created_at_ms=NOW_MS,
                expires_at_ms=NOW_MS,
            )

    def test_float_in_payload_rejected(self, alice_identity):
        with pytest.raises((TransportEnvelopeRejected, TypeError)):
            _signed(alice_identity, payload={"price": 1.5})

    def test_payload_hash_mismatch_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        tampered = replace_payload(envelope, {"body": "evil"})
        ok, reason = validate_envelope(tampered)
        assert not ok and "payload hash" in reason

    def test_message_id_mismatch_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.message_id = "sha256:" + "0" * 64
        ok, reason = validate_envelope(envelope)
        assert not ok and "message id" in reason

    def test_signature_tamper_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        sig = list(envelope.signature)
        sig[10] = "A" if sig[10] != "A" else "B"
        envelope.signature = "".join(sig)
        ok, reason = validate_envelope(envelope, now_ms=NOW_MS + 1_000)
        assert not ok and "signature" in reason

    def test_wrong_signer_rejected(self, alice_identity, bob_identity):
        envelope = _signed(alice_identity)
        envelope.sender_did = bob_identity.as_did()
        ok, reason = validate_envelope(envelope, now_ms=NOW_MS + 1_000)
        assert not ok

    def test_missing_signature_rejected_when_required(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.signature = ""
        ok, reason = validate_envelope(envelope)
        assert not ok and "missing" in reason

    def test_bad_kind_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="kind"):
            _signed(alice_identity, kind="Not A Kind!")

    def test_bad_recipient_scheme_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="recipient"):
            _signed(alice_identity, recipient="https://example.com")

    def test_bad_recipient_did_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="recipient"):
            _signed(alice_identity, recipient="did:key:zzzz")

    def test_path_traversal_recipient_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="recipient"):
            _signed(alice_identity, recipient="dao:../etc")

    def test_bad_nonce_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="nonce"):
            _signed(alice_identity, nonce="short")

    def test_routing_unknown_field_rejected(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.routing = dict(envelope.routing, cost="free")
        ok, reason = validate_envelope(envelope)
        assert not ok and "routing" in reason

    def test_hop_count_over_limit_rejected(self, alice_identity):
        envelope = _signed(alice_identity, hop_limit=1)
        envelope.routing = dict(envelope.routing, hop_count=2)
        ok, reason = validate_envelope(envelope)
        assert not ok and "hop_count" in reason

    def test_hop_limit_over_maximum_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="hop_limit"):
            _signed(alice_identity, hop_limit=MAX_HOP_LIMIT + 1)

    def test_dao_id_traversal_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="dao_id"):
            _signed(alice_identity, dao_id="../../etc")

    def test_payload_depth_rejected(self, alice_identity):
        deep = current = {}
        for _ in range(24):
            current["child"] = {}
            current = current["child"]
        with pytest.raises((TransportEnvelopeRejected, RecursionError)):
            _signed(alice_identity, payload=deep)

    def test_payload_too_large_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected, match="too large"):
            _signed(alice_identity, payload={"blob": "x" * (MAX_PAYLOAD_BYTES + 1)})

    def test_non_object_payload_rejected(self, alice_identity):
        with pytest.raises(TransportEnvelopeRejected):
            sign_envelope(
                alice_identity,
                kind="mission.announcement",
                recipient="dao:core",
                payload=[1, 2, 3],
                created_at_ms=NOW_MS,
                expires_at_ms=NOW_MS + 1_000,
            )

    def test_nonce_uniqueness_by_default(self, alice_identity):
        first = _signed(alice_identity)
        second = _signed(alice_identity)
        assert first.nonce != second.nonce

    def test_new_nonce_bounds(self):
        assert len(new_nonce()) == 32
        assert len(new_nonce(16)) == 16
        with pytest.raises(ValueError):
            new_nonce(8)

    def test_default_routing(self, alice_identity):
        envelope = _signed(alice_identity)
        assert envelope.routing["hop_limit"] == DEFAULT_HOP_LIMIT
        assert envelope.routing["hop_count"] == 0

    def test_reply_to_signed(self, alice_identity):
        envelope = _signed(alice_identity, reply_to="channel:backlog")
        assert envelope.routing["reply_to"] == "channel:backlog"
        ok, reason = validate_envelope(envelope, now_ms=NOW_MS + 1_000)
        assert ok, reason

    def test_tampered_forwarded_hop_breaks_nothing_but_mutation_detected(self, alice_identity):
        """A relay cannot decrement hop_count below the author's value silently
        in a way that changes semantics — but since hop_count is unsigned and
        monotonic by convention, a *drop* back to 0 would only cause extra
        forwarding, never authority. Verify the digest detects the change."""

        envelope = _signed(alice_identity, hop_limit=2)
        forwarded = forward_envelope(envelope)
        mutated = copy.deepcopy(forwarded)
        mutated.routing["hop_count"] = 0
        assert envelope_digest(mutated) != envelope_digest(forwarded)

    def test_validate_rejects_non_envelope(self):
        ok, reason = validate_envelope({"not": "an envelope"})
        assert not ok and "TransportEnvelope" in reason


# ─────────────────── adversarial review round 2 (bug A) ───────────────────


class TestValidationContract:
    """validate_envelope must RETURN (False, reason) — never raise — for
    any hostile input, including out-of-range integers (review bug A)."""

    def test_huge_created_at_returns_rejection(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.created_at_ms = 10**20
        ok, reason = validate_envelope(envelope)
        assert ok is False
        assert "safe integer" in reason

    def test_huge_expires_at_returns_rejection(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.expires_at_ms = 10**20
        ok, reason = validate_envelope(envelope)
        assert ok is False
        assert "safe integer" in reason

    def test_bool_timestamp_returns_rejection(self, alice_identity):
        envelope = _signed(alice_identity)
        envelope.created_at_ms = True
        ok, reason = validate_envelope(envelope)
        assert ok is False and "integer" in reason

    def test_huge_now_ms_returns_rejection(self, alice_identity):
        envelope = _signed(alice_identity)
        ok, reason = validate_envelope(envelope, now_ms=10**20)
        assert ok is False and "now_ms" in reason

    def test_huge_int_via_inbox_never_raises(self, tmp_path, alice_identity):
        """Full pipeline: a hostile envelope with an oversized timestamp must
        come back as an InboxDecision rejection, not an exception."""

        from nth_dao.delivery.inbox import DeliveryInbox

        inbox = DeliveryInbox(tmp_path / "delivery", clock=lambda: NOW_MS)
        envelope = _signed(alice_identity)
        envelope.created_at_ms = 10**20
        decision = inbox.accept(envelope, now_ms=NOW_MS)
        assert decision.accepted is False
        assert "safe integer" in decision.reason


# ─────────────────── adversarial review round 3 (bug J) ───────────────────


class TestReplyToStrictness:
    def test_explicit_null_reply_to_rejected(self, alice_identity):
        """Bug J: a foreign implementation signing routing.reply_to=null
        must be rejected — absent and null must not be two encodings of one
        semantic value."""

        from nth_dao.b64u import b64u_encode

        envelope = _signed(alice_identity, hop_limit=2)
        data = envelope.to_dict()
        data["routing"] = dict(data["routing"], reply_to=None)
        # re-derive content address + signature as the foreign sender would
        probe = TransportEnvelope.from_dict(data)
        data["message_id"] = _content_address_hex(probe)
        body = dict(data)
        body.pop("signature")
        data["signature"] = b64u_encode(alice_identity.sign(canonical_json(body)))
        hostile = TransportEnvelope.from_dict(data)
        ok, reason = validate_envelope(hostile, now_ms=NOW_MS + 1_000)
        assert ok is False
        assert "reply_to" in reason


def _content_address_hex(envelope):
    import hashlib


    body = envelope.content_body()
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


# ─────────────────── adversarial review round 19 (bug FF-5) ───────────────────


class TestEnvelopeDigestDictContract:
    def test_digest_rejects_unknown_fields(self, alice_identity):
        """Bug FF-5: envelope_digest(uncalid dict) used to silently digest
        any shape — now the field set is checked first."""

        envelope = _signed(alice_identity)
        hostile = dict(envelope.to_dict())
        hostile["extra"] = True
        with pytest.raises(TransportEnvelopeRejected, match="unknown fields"):
            envelope_digest(hostile)

    def test_digest_rejects_missing_fields(self, alice_identity):
        envelope = _signed(alice_identity)
        hostile = dict(envelope.to_dict())
        del hostile["nonce"]
        with pytest.raises(TransportEnvelopeRejected, match="missing"):
            envelope_digest(hostile)

    def test_digest_accepts_exact_envelope_shape(self, alice_identity):
        envelope = _signed(alice_identity)
        exact = envelope.to_dict()
        assert envelope_digest(exact) == envelope_digest(envelope)
