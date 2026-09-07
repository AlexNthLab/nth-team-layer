"""Tests for the file-bundle transport — the offline carry baseline."""

from __future__ import annotations

import json

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.delivery.transports.file_bundle import (
    BUNDLE_SUFFIX,
    FileBundleRejected,
    FileBundleTransport,
)

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


def _envelope(alice_identity, payload=None):
    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient="dao:core",
        payload={"body": "hi"} if payload is None else payload,
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 60_000,
    )


@pytest.fixture()
def exchange(tmp_path):
    return tmp_path / "exchange"


@pytest.fixture()
def sender_transport(exchange, alice_identity):
    return FileBundleTransport(
        exchange, alice_identity, state_dir=exchange / ".state-alice",
        clock=lambda: NOW_MS,
    )


class TestBundleRoundtrip:
    def test_send_then_poll_delivers(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob",
            clock=lambda: NOW_MS,
        )
        envelope = _envelope(alice_identity)
        assert sender.send(envelope).accepted
        received = receiver.poll()
        assert len(received) == 1
        assert received[0].message_id == envelope.message_id

    def test_repoll_does_not_double_deliver(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob",
            clock=lambda: NOW_MS,
        )
        sender.send(_envelope(alice_identity))
        assert len(receiver.poll()) == 1
        assert receiver.poll() == []

    def test_receiver_restart_does_not_double_deliver(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        first = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert len(first.poll()) == 1
        second = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert second.poll() == []

    def test_bundle_file_is_signed_canonical_json(self, exchange, alice_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        bundles = list(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        assert len(bundles) == 1
        data = json.loads(bundles[0].read_text())
        assert data["protocol"] == "nth-delivery-file-bundle"
        assert data["version"] == 1
        assert data["sender_did"] == alice_identity.as_did()
        assert data["signature"]
        # canonical bytes on disk: re-encoding matches
        assert canonical_json(data) == bundles[0].read_bytes()

    def test_partial_poll_does_not_discard_bundle_tail(
        self, exchange, alice_identity, bob_identity
    ):
        sender = sender_transport_factory(exchange, alice_identity)
        originals = [
            _envelope(alice_identity, payload={"n": index}) for index in range(3)
        ]
        sender._write_bundle(sender._build_bundle(originals))
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=exchange / ".state-bob",
            clock=lambda: NOW_MS,
        )

        first = receiver.poll(max_items=1)
        remainder = receiver.poll(max_items=10)

        assert [item.message_id for item in first] == [originals[0].message_id]
        assert [item.message_id for item in remainder] == [
            item.message_id for item in originals[1:]
        ]


class TestBundleHostility:
    def test_tampered_bundle_rejected(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        bundle_path = next(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        data = json.loads(bundle_path.read_text())
        data["created_at_ms"] += 1  # any body change breaks the signature
        bundle_path.write_bytes(canonical_json(data))
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert receiver.poll() == []

    def test_corrupt_json_skipped_not_fatal(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        junk = exchange / "junk.nthbundle"
        junk.write_bytes(b"{not json")
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        received = receiver.poll()
        assert len(received) == 1  # the good bundle survives the bad one

    def test_unknown_fields_rejected(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        bundle_path = next(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        data = json.loads(bundle_path.read_text())
        data["surprise"] = True
        bundle_path.write_bytes(canonical_json(data))
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert receiver.poll() == []

    def test_wrong_version_rejected(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        bundle_path = next(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        data = json.loads(bundle_path.read_text())
        # re-sign as v99 with bob's key over the modified body
        data["version"] = 99
        data["sender_did"] = bob_identity.as_did()
        from nth_dao.b64u import b64u_encode

        data["signature"] = b64u_encode(
            bob_identity.sign(canonical_json(
                {k: v for k, v in data.items() if k != "signature"}
            ))
        )
        bundle_path.write_bytes(canonical_json(data))
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert receiver.poll() == []

    def test_unsigned_envelope_not_sendable(self, exchange, alice_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        envelope = _envelope(alice_identity)
        envelope.signature = ""
        result = sender.send(envelope)
        assert not result.accepted and "invalid-envelope" in result.error_code


class TestBundleCaps:
    def test_crypto_required(self, exchange, monkeypatch):
        import nth_dao.delivery.transports.file_bundle as fb

        monkeypatch.setattr(fb, "_NACL_AVAILABLE", False)
        from nth_dao.identity import AgentIdentity

        with pytest.raises(FileBundleRejected, match="crypto unavailable"):
            FileBundleTransport(exchange, AgentIdentity.generate(label="x"))

    def test_capabilities_declare_offline_broadcast(self, sender_transport):
        caps = sender_transport.capabilities
        assert caps.realtime is False
        assert caps.broadcast is True
        assert caps.privacy_level == 2
        assert caps.external_infrastructure is False


def sender_transport_factory(exchange, identity):
    return FileBundleTransport(
        exchange, identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
    )


# ──────────────── adversarial review round 2 (bugs E + F + G) ────────────────


class TestReviewRoundTwo:
    def test_oversized_bundle_skipped_before_read(self, exchange, alice_identity, bob_identity, monkeypatch):
        """Bug E: a hostile courier drops a huge file — poll must stat-and-
        skip it without ever reading it into memory."""

        import nth_dao.delivery.transports.file_bundle as fb

        sender = FileBundleTransport(
            exchange, alice_identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
        )
        sender.send(_envelope(alice_identity))
        # hostile: a 64 KB junk bundle while the cap is patched down to 4 KB
        # (a legitimate single-envelope bundle is well under 4 KB)
        junk = exchange / "junk-big.nthbundle"
        junk.write_bytes(b"x" * 65_536)
        monkeypatch.setattr(fb, "BUNDLE_MAX_FILE_BYTES", 4_096)

        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        received = receiver.poll()
        assert len(received) == 1  # good bundle survives, big junk skipped

    def test_no_tmp_leftovers_after_send(self, exchange, alice_identity):
        """Bug F: the atomic write must use a unique temp name and clean up —
        no .tmp-* files may linger after a send."""

        sender = FileBundleTransport(
            exchange, alice_identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
        )
        sender.send(_envelope(alice_identity))
        sender.send(_envelope(alice_identity, payload={"n": 2}))
        leftovers = list(exchange.glob(".tmp-*"))
        assert leftovers == []
        bundles = list(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        assert len(bundles) == 2

    def test_version_bool_rejected(self, exchange, alice_identity, bob_identity):
        """Bug G: JSON `true` equals Python 1 — a bundle claiming
        version=true must be rejected by a strict type check."""

        from nth_dao.b64u import b64u_encode
        from nth_dao.delivery.transports.file_bundle import _bundle_body

        envelope = _envelope(alice_identity)
        envelope_json = canonical_json(envelope.to_dict()).decode("utf-8")
        import hashlib as _hashlib

        digest = "sha256:" + _hashlib.sha256(
            (envelope_json + "\n").encode("utf-8")
        ).hexdigest()
        bundle = {
            "protocol": "nth-delivery-file-bundle",
            "version": True,  # hostile: bool sneaks past `== 1`
            "sender_did": alice_identity.as_did(),
            "created_at_ms": NOW_MS,
            "envelopes": [envelope_json],
            "envelopes_sha256": digest,
        }
        bundle["signature"] = b64u_encode(
            alice_identity.sign(canonical_json(_bundle_body(bundle)))
        )
        # the exchange dir is created by the transports; receiver first so the
        # directory exists before the hostile bundle is dropped
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        path = exchange / "bundle-bool-version.nthbundle"
        path.write_bytes(canonical_json(bundle))
        assert receiver.poll() == []


# ──────────────── adversarial review round 3 (bug K) ────────────────


class TestImportJournalCrossProcess:
    def test_shared_state_dir_dedups_across_instances(self, exchange, alice_identity, bob_identity):
        """Bug K: two receiver processes sharing one state dir must dedup
        imports through the (now lock-protected) journal — a bundle imported
        by one is not re-imported by the other."""

        sender = FileBundleTransport(
            exchange, alice_identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
        )
        sender.send(_envelope(alice_identity))
        receiver_one = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-shared", clock=lambda: NOW_MS
        )
        receiver_two = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-shared", clock=lambda: NOW_MS
        )
        assert len(receiver_one.poll()) == 1
        # the second process folds the same journal: no double delivery
        import time as _t

        _t.sleep(0.02)
        assert receiver_two.poll() == []
