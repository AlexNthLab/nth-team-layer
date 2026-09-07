"""Tests for the HTTPS federation transport and stdlib ingest server."""

from __future__ import annotations

import json

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import (
    TransportEnvelopeRejected,
    envelope_digest,
    sign_envelope,
)
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.transports.federation import (
    FederationIngestServer,
    FederationTransport,
    FederationTransportError,
    ack_from_envelope,
    validate_peer_url,
)
from nth_dao.delivery.transports.file_bundle import FileBundleTransport
from nth_dao.nostr import NostrAdapterUnavailable, NostrKeys

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
        expires_at_ms=NOW_MS + 120_000,
    )


@pytest.fixture()
def nostr_keys():
    try:
        return NostrKeys.generate()
    except NostrAdapterUnavailable:
        pytest.skip("nostr optional extra is not installed")


@pytest.fixture()
def server(tmp_path, bob_identity):
    inbox = DeliveryInbox(tmp_path / "bob", clock=lambda: NOW_MS + 1_000)
    server = FederationIngestServer(inbox, host="127.0.0.1", port=0)
    server.start()
    yield server, inbox
    server.stop()


class TestPeerUrlValidation:
    def test_https_anywhere(self):
        assert validate_peer_url("https://peer.example.com") == "https://peer.example.com"
        assert validate_peer_url("https://1.2.3.4:8443/x") == "https://1.2.3.4:8443/x"

    def test_http_loopback_allowed(self):
        assert validate_peer_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
        assert validate_peer_url("http://localhost:9000/") == "http://localhost:9000"

    def test_http_non_loopback_rejected(self):
        with pytest.raises(FederationTransportError, match="https"):
            validate_peer_url("http://peer.example.com")

    def test_credentials_rejected(self):
        with pytest.raises(FederationTransportError):
            validate_peer_url("https://user:pass@peer.example.com")

    def test_query_and_fragment_rejected(self):
        with pytest.raises(FederationTransportError):
            validate_peer_url("https://peer.example.com/?x=1")
        with pytest.raises(FederationTransportError):
            validate_peer_url("https://peer.example.com/#frag")

    def test_whitespace_and_empty_rejected(self):
        with pytest.raises(FederationTransportError):
            validate_peer_url("  ")
        with pytest.raises(FederationTransportError):
            validate_peer_url("")
        with pytest.raises(FederationTransportError):
            validate_peer_url("https://peer .example.com")


class TestFederationTransport:
    def test_requires_peers(self):
        with pytest.raises(ValueError, match="peer_urls"):
            FederationTransport(peer_urls=[])

    @pytest.mark.parametrize("timeout", [True, float("nan"), float("inf"), 0])
    def test_timeout_must_be_a_finite_number(self, timeout):
        with pytest.raises(ValueError, match="timeout"):
            FederationTransport(peer_urls=["https://a.example.com"], timeout=timeout)

    def test_rejects_duplicate_peers(self):
        with pytest.raises(ValueError, match="duplicates"):
            FederationTransport(peer_urls=["https://a.example.com", "https://a.example.com"])

    def test_unreachable_peers_fail_closed(self, alice_identity):
        transport = FederationTransport(peer_urls=["http://127.0.0.1:59999"])
        result = transport.send(_envelope(alice_identity))
        assert not result.accepted
        assert result.error_code == "peers-unreachable"

    def test_capabilities_declare_broadcast_push(self):
        transport = FederationTransport(peer_urls=["https://a.example.com"])
        caps = transport.capabilities
        assert caps.unicast is False
        assert caps.broadcast is True
        assert caps.realtime is False
        assert caps.privacy_level == 1
        assert transport.poll() == []

    def test_direct_recipient_requires_an_explicit_route(
        self, server, alice_identity, bob_identity
    ):
        httpd, inbox = server
        transport = FederationTransport(peer_urls=[httpd.url])
        envelope = _envelope(alice_identity)
        envelope = sign_envelope(
            alice_identity,
            kind=envelope.kind,
            recipient=bob_identity.as_did(),
            payload=envelope.payload,
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 120_000,
        )
        result = transport.send(envelope)
        assert not result.accepted
        assert result.error_code == "recipient-route-required"
        assert inbox.entry_count() == 0

    def test_direct_recipient_uses_only_its_bound_endpoint(
        self, tmp_path, alice_identity, bob_identity
    ):
        from nth_dao.identity import AgentIdentity

        carol_identity = AgentIdentity.generate(label="carol")
        bob_inbox = DeliveryInbox(tmp_path / "bob-direct", clock=lambda: NOW_MS + 1)
        carol_inbox = DeliveryInbox(tmp_path / "carol-direct", clock=lambda: NOW_MS + 1)
        bob_server = FederationIngestServer(bob_inbox, host="127.0.0.1", port=0)
        carol_server = FederationIngestServer(carol_inbox, host="127.0.0.1", port=0)
        bob_server.start()
        carol_server.start()
        try:
            transport = FederationTransport(
                peer_urls=[carol_server.url],
                recipient_urls={bob_identity.as_did(): bob_server.url},
            )
            assert transport.capabilities.unicast is True
            envelope = sign_envelope(
                alice_identity,
                kind="channel.message",
                recipient=bob_identity.as_did(),
                payload={"body": "bob only"},
                created_at_ms=NOW_MS,
                expires_at_ms=NOW_MS + 120_000,
            )
            assert transport.send(envelope).accepted
            assert bob_inbox.seen(envelope.message_id)
            assert not carol_inbox.seen(envelope.message_id)
            assert carol_identity.as_did() != bob_identity.as_did()
        finally:
            carol_server.stop()
            bob_server.stop()


class TestIngestServer:

    def test_roundtrip_accepts_valid_envelope(self, server, alice_identity):
        httpd, inbox = server
        transport = FederationTransport(peer_urls=[httpd.url])
        envelope = _envelope(alice_identity)
        result = transport.send(envelope)
        assert result.accepted, result.error_code
        assert inbox.entry_count() == 1
        assert inbox.seen(envelope.message_id)

    def test_duplicate_delivery_is_idempotent_success(self, server, alice_identity):
        httpd, inbox = server
        transport = FederationTransport(peer_urls=[httpd.url])
        envelope = _envelope(alice_identity)
        assert transport.send(envelope).accepted
        # redelivering the same envelope still answers 200
        assert transport.send(envelope).accepted
        assert inbox.entry_count() == 1

    def test_two_transports_one_server(self, server, alice_identity):
        """Federated broadcast: two senders, one ingest point, both land."""

        httpd, inbox = server
        first = FederationTransport(peer_urls=[httpd.url], name="fed-1")
        second = FederationTransport(peer_urls=[httpd.url], name="fed-2")
        assert first.send(_envelope(alice_identity, payload={"n": 1})).accepted
        assert second.send(_envelope(alice_identity, payload={"n": 2})).accepted
        assert inbox.entry_count() == 2

    def test_malformed_body_returns_400(self, server):
        import urllib.error
        import urllib.request

        httpd, _ = server
        request = urllib.request.Request(
            httpd.ingest_url, data=b"{not json", method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
            raise AssertionError("expected HTTP 400")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400

    def test_noncanonical_json_never_bypasses_wire_check(self, server, alice_identity):
        import urllib.error
        import urllib.request

        httpd, inbox = server
        envelope = _envelope(alice_identity)
        noncanonical = json.dumps(envelope.to_dict(), indent=2).encode("utf-8")
        request = urllib.request.Request(
            httpd.ingest_url,
            data=noncanonical,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        assert raised.value.code == 422
        assert inbox.entry_count() == 0

    def test_ingest_query_is_not_an_alias_for_exact_endpoint(self, server):
        import urllib.error
        import urllib.request

        httpd, _ = server
        request = urllib.request.Request(
            httpd.ingest_url + "?shadow=1",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        assert raised.value.code == 404

    def test_unknown_path_404(self, server):
        import urllib.error
        import urllib.request

        httpd, _ = server
        for _ in range(5):
            request = urllib.request.Request(
                httpd.url + "/elsewhere",
                data=b"{}",
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with pytest.raises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=5)
            assert raised.value.code == 404
            assert raised.value.headers["Connection"] == "close"

    def test_oversized_body_413(self, server):
        import urllib.error
        import urllib.request

        httpd, _ = server
        # raw oversized body: the Content-Length gate fires before parsing
        body = b"x" * 600_000
        request = urllib.request.Request(
            httpd.ingest_url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(request, timeout=10)
            raise AssertionError("expected HTTP 413")
        except urllib.error.HTTPError as exc:
            assert exc.code == 413

    def test_expired_envelope_422(self, server, alice_identity):
        import urllib.error
        import urllib.request

        httpd, _ = server
        envelope = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"n": 1},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 1_000,
        )
        body = canonical_json(envelope.to_dict())
        request = urllib.request.Request(
            httpd.ingest_url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
            raise AssertionError("expected HTTP 422")
        except urllib.error.HTTPError as exc:
            assert exc.code == 422
            payload = json.loads(exc.read())
            assert "expired" in payload["reason"]


class TestAckEnvelope:
    def test_ack_roundtrip_through_envelope(self, tmp_path, alice_identity, bob_identity):
        """The ACK travels back as a signed envelope; only the receiver's
        identity can vouch for it."""

        alice_inbox = DeliveryInbox(tmp_path / "alice", clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 1_000,
        )
        ack_envelope = sign_envelope(
            bob_identity,
            kind="delivery.ack",
            recipient=alice_identity.as_did(),
            payload={"ack": ack.to_dict()},
            created_at_ms=NOW_MS + 1_100,
            expires_at_ms=NOW_MS + 61_100,
        )
        # bob's own inbox accepts his outgoing ack envelope in real flows via
        # loopback; here we validate the unwrap on alice's side
        assert alice_inbox.accept(ack_envelope, now_ms=NOW_MS + 1_500).accepted
        unwrapped = ack_from_envelope(ack_envelope)
        assert unwrapped.message_id == envelope.message_id

    def test_wrong_kind_rejected(self, alice_identity, bob_identity):
        envelope = _envelope(alice_identity)
        with pytest.raises(ValueError, match="not a delivery.ack"):
            ack_from_envelope(envelope)

    def test_author_must_be_the_ack_receiver(self, alice_identity, bob_identity):
        ack = sign_ack(
            bob_identity,
            message_id="sha256:" + "3" * 64,
            envelope_sha256="sha256:" + "4" * 64,
            received_at_ms=NOW_MS,
        )
        # envelope authored by alice but the ack claims bob is the receiver
        forged = sign_envelope(
            alice_identity,
            kind="delivery.ack",
            recipient=alice_identity.as_did(),
            payload={"ack": ack.to_dict()},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        with pytest.raises(ValueError, match="does not match the envelope author"):
            ack_from_envelope(forged)

    def test_payload_shape_strict(self, alice_identity, bob_identity):
        ack = sign_ack(
            bob_identity,
            message_id="sha256:" + "1" * 64,
            envelope_sha256="sha256:" + "2" * 64,
            received_at_ms=NOW_MS,
        )
        envelope = sign_envelope(
            bob_identity,
            kind="delivery.ack",
            recipient=alice_identity.as_did(),
            payload={"ack": ack.to_dict(), "extra": 1},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        with pytest.raises(ValueError, match="exactly one"):
            ack_from_envelope(envelope)


class TestClientSideValidation:
    def test_send_unsigned_envelope_rejected_client_side(self, alice_identity):
        transport = FederationTransport(peer_urls=["https://a.example.com"])
        envelope = _envelope(alice_identity)
        envelope.signature = ""
        result = transport.send(envelope)
        assert not result.accepted
        assert "invalid-envelope" in result.error_code


# ─────────────────── adversarial review round 8 (bug AJ) ───────────────────


class TestContentLengthStrictness:
    def test_unicode_content_length_returns_400_not_crash(self, server):
        """Bug AJ: '²'.isdigit() is True but int('²') explodes — a hostile
        Content-Length header must get a clean 400, never kill the thread.
        Raw sockets (urllib's own header handling would obscure the server
        behavior under test)."""

        import socket

        httpd, _ = server
        port = httpd._httpd.server_address[1]
        for hostile in ("²", "１２３", "-5", "1e3", ""):
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            header_value = hostile.encode("latin-1", "replace")
            request = (
                b"POST /delivery/ingest HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + header_value + b"\r\n"
                b"\r\n{}"
            )
            sock.sendall(request)
            response = sock.recv(4096)
            sock.close()
            status = int(response.split(b"\r\n", 1)[0].split()[1])
            assert status == 400, (hostile, response[:60])

        # the server is still alive afterwards
        transport = FederationTransport(peer_urls=[httpd.url])
        from nth_dao.identity import AgentIdentity

        ident = AgentIdentity.generate(label="still-alive")
        envelope = _envelope(ident)
        assert transport.send(envelope).accepted


# ─────────────────── adversarial review round 15 ───────────────────


class TestPublicTierPolicy:
    def test_private_did_recipient_rejected_on_public_tier(self, alice_identity, nostr_keys):
        """Bug CC-b: single-recipient (did:key) envelopes are private traffic
        and must be refused on the world-readable relay tier."""

        from nth_dao.delivery.envelope import TransportEnvelopeRejected
        from nth_dao.identity import AgentIdentity
        from nth_dao.nostr import envelope_event

        bob = AgentIdentity.generate(label="bob")
        private_dm = sign_envelope(
            alice_identity,
            kind="dm.message",
            recipient=bob.as_did(),
            payload={"secret": "private payload"},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        with pytest.raises(TransportEnvelopeRejected, match="broadcast traffic only"):
            envelope_event(private_dm, nostr_keys, created_at_seconds=NOW_MS // 1000)
        # broadcast recipients remain fine
        assert envelope_event(
            _envelope(alice_identity), nostr_keys, created_at_seconds=NOW_MS // 1000
        ) is not None


class TestBindingEnforcement:
    def test_publish_with_verified_binding_succeeds(self, alice_identity, nostr_keys):
        import time as time_mod

        from nth_dao.nostr import envelope_event, sign_key_binding

        binding = sign_key_binding(
            alice_identity,
            nostr_keys=nostr_keys,
            created_at_ms=int(time_mod.time() * 1000),
        )
        envelope = _envelope(alice_identity)
        event = envelope_event(
            envelope,
            nostr_keys,
            created_at_seconds=int(time_mod.time()),
            binding=binding,
        )
        assert event.author().to_hex() == nostr_keys.public_key_hex

    def test_publish_with_mismatched_key_rejected(self, alice_identity, nostr_keys):
        """Bug CC-c: an envelope must not be published under a relay key that
        no verified binding delivers."""

        import time as time_mod

        from nth_dao.nostr import envelope_event, sign_key_binding

        other = NostrKeys.generate()
        binding = sign_key_binding(
            alice_identity,
            nostr_keys=other,
            created_at_ms=int(time_mod.time() * 1000),
        )
        envelope = _envelope(alice_identity)
        with pytest.raises(
            TransportEnvelopeRejected,
            match="does not name the publishing key",
        ):
            envelope_event(
                envelope,
                nostr_keys,
                created_at_seconds=int(time_mod.time()),
                binding=binding,
            )

    def test_forged_binding_signature_rejected(self, alice_identity, nostr_keys, tmp_path):
        """The publish-side gate verifies the binding signature against the
        DID decoded from the binding itself — no identity object needed."""

        import time as time_mod
        from dataclasses import replace

        from nth_dao.nostr import envelope_event, sign_key_binding

        binding = sign_key_binding(
            alice_identity,
            nostr_keys=nostr_keys,
            created_at_ms=int(time_mod.time() * 1000),
        )
        forged = replace(binding, signature="00" * 64)
        envelope = _envelope(alice_identity)
        with pytest.raises(TransportEnvelopeRejected, match="binding invalid"):
            envelope_event(
                envelope,
                nostr_keys,
                created_at_seconds=int(time_mod.time()),
                binding=forged,
            )


class TestImportedJournalRotation:
    def test_journal_rotates_at_cap(self, tmp_path, alice_identity, bob_identity, monkeypatch):
        """Bug CC-a: the imported journal is bounded — past the cap it
        rotates to the newest half instead of growing forever."""

        import nth_dao.delivery.transports.file_bundle as fb

        monkeypatch.setattr(fb, "_IMPORTED_JOURNAL_CAP", 1_024)
        exchange = tmp_path / "exchange"
        sender = FileBundleTransport(
            exchange, alice_identity, state_dir=exchange / ".s-alice", clock=lambda: NOW_MS
        )
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".s-bob", clock=lambda: NOW_MS
        )
        sent = []
        for i in range(30):
            envelope = _envelope(alice_identity, payload={"n": i})
            sender.send(envelope)
            sent.append(envelope)
            receiver.poll()  # import (rotation may drop old digests)
        latest = _envelope(alice_identity, payload={"n": 999})
        sender.send(latest)
        sent.append(latest)
        receiver.poll()

        journal = exchange / ".s-bob" / "imported.jsonl"
        assert journal.stat().st_size <= fb._IMPORTED_JOURNAL_CAP + 2_048

        # design contract: every sent envelope is DELIVERABLE across
        # rotations — poll until stable, the set of seen message ids must
        # cover all 31 sends, with no double-import inside one poll
        all_polled: list = []
        for _ in range(3):
            polled = receiver.poll(max_items=256)
            all_polled.extend(polled)
            # within ONE poll call there must be no duplicate message id
            poll_ids = [envelope.message_id for envelope in polled]
            assert len(poll_ids) == len(set(poll_ids))
        seen_ids = {envelope.message_id for envelope in all_polled}
        expected_ids = {envelope.message_id for envelope in sent}
        assert seen_ids >= expected_ids, (
            f"missing {len(expected_ids - seen_ids)} envelopes after rotation"
        )
