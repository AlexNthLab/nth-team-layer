"""Tests for nth_dao.delivery.acknowledgement — signed delivery ACKs."""

from __future__ import annotations

import pytest

from nth_dao.delivery.acknowledgement import (
    ACK_STATUS_RECEIVED,
    DeliveryAck,
    DeliveryAckRejected,
    ack_digest,
    sign_ack,
    validate_ack,
)
from nth_dao.delivery.envelope import MAX_CLOCK_SKEW_MS, envelope_digest, sign_envelope

pytest.importorskip("nacl")

NOW_MS = 1_750_000_000_000


@pytest.fixture()
def alice_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def bob_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="bob")


@pytest.fixture()
def envelope(alice_identity):
    return sign_envelope(
        alice_identity,
        kind="mission.announcement",
        recipient="dao:core",
        payload={"body": "hello"},
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 60_000,
    )


class TestAckHappyPath:
    def test_signed_ack_validates(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 100,
        )
        ok, reason = validate_ack(ack, now_ms=NOW_MS + 200)
        assert ok, reason
        assert ack.status == ACK_STATUS_RECEIVED

    def test_ack_roundtrip_via_dict(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 100,
        )
        restored = DeliveryAck.from_dict(ack.to_dict())
        ok, reason = validate_ack(restored, now_ms=NOW_MS + 200)
        assert ok, reason
        assert ack_digest(restored) == ack_digest(ack)

    def test_ack_is_stable_and_dedupable(self, bob_identity, envelope):
        first = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 100,
        )
        second = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 100,
        )
        # deterministic body: same inputs -> same digest; signature deterministic
        assert ack_digest(first) == ack_digest(second)


class TestAckNegative:
    def test_boolean_version_rejected(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        ack.version = True
        ok, reason = validate_ack(ack, now_ms=NOW_MS + 100)
        assert not ok and "version" in reason

    def test_boolean_now_rejected(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        ok, reason = validate_ack(ack, now_ms=True)
        assert not ok and "now_ms" in reason

    def test_unknown_field_rejected(self, bob_identity, envelope):
        data = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        ).to_dict()
        data["extra"] = 1
        with pytest.raises(DeliveryAckRejected, match="missing or unknown"):
            DeliveryAck.from_dict(data)

    def test_tampered_message_id_breaks_signature(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        ack.message_id = "sha256:" + "f" * 64
        ok, reason = validate_ack(ack, now_ms=NOW_MS + 100)
        assert not ok and "signature" in reason

    def test_future_dated_ack_rejected(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + MAX_CLOCK_SKEW_MS + 1,
        )
        ok, reason = validate_ack(ack, now_ms=NOW_MS)
        assert not ok and "future" in reason

    def test_bad_receiver_did_rejected(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        ack.receiver_did = "did:key:zzzz"
        ok, reason = validate_ack(ack, now_ms=NOW_MS + 100)
        assert not ok

    def test_bad_status_rejected(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        ack.status = "accepted-and-settled"
        ok, reason = validate_ack(ack, now_ms=NOW_MS + 100)
        assert not ok and "status" in reason

    def test_missing_signature_rejected(self, bob_identity, envelope):
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS,
        )
        ack.signature = ""
        ok, reason = validate_ack(ack)
        assert not ok and "missing" in reason

    def test_non_content_address_rejected(self, bob_identity):
        with pytest.raises(DeliveryAckRejected, match="content address"):
            sign_ack(
                bob_identity,
                message_id="not-a-hash",
                envelope_sha256="sha256:" + "a" * 64,
                received_at_ms=NOW_MS,
            )

    def test_float_rejected(self, bob_identity, envelope):
        ack = DeliveryAck(
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            receiver_did=bob_identity.as_did(),
            received_at_ms=NOW_MS + 0.5,
        )
        ok, reason = validate_ack(ack)
        assert not ok and "integer" in reason

    def test_non_object_rejected(self):
        with pytest.raises(DeliveryAckRejected, match="JSON object"):
            DeliveryAck.from_dict(["nope"])

    def test_validate_rejects_non_ack(self):
        ok, reason = validate_ack({"nope": True})
        assert not ok and "DeliveryAck" in reason
