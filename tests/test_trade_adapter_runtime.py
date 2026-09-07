"""Tests for the Slice-B adapter runtime — executing an approved Hook.

The reference adapter (written to a temp file per test) speaks
``nth-trade-adapter-rpc/1`` over stdio: handshake ack, then one hook
response. Its result ``{"status": "ok"}`` validates against the output
schema used by the agreement test chain, so the same artifact works both
for runtime unit tests and for the end-to-end coordinator flow.
"""

from __future__ import annotations

import hashlib
import json
import sys
import textwrap
from pathlib import Path

import pytest

from nth_dao.trade_rules.adapter_runtime import (
    AdapterHookFailed,
    AdapterHookRejected,
    SubprocessAdapterRunner,
    content_descriptor,
    encode_handshake,
    parse_handshake_ack,
    parse_response,
)
from nth_dao.trade_rules.execution_adapter import build_execution_adapter

pytest.importorskip("nacl")

REFERENCE_ADAPTER = textwrap.dedent(
    """
    import json
    import sys


    def main():
        handshake = json.loads(sys.stdin.readline())
        if (
            handshake.get("protocol") != "nth-trade-adapter-rpc"
            or handshake.get("version") != 1
        ):
            sys.stdout.write(json.dumps({"ok": False, "error": "bad handshake"}) + "\\n")
            return 2
        sys.stdout.write(json.dumps({"ok": True}) + "\\n")
        sys.stdout.flush()
        request = json.loads(sys.stdin.readline())
        # deterministic, schema-exact result: the agreement test chain's
        # output schema requires {"status": "ok"} and its content resolver
        # preloads exactly these canonical bytes
        result = {"status": "ok"}
        # hostile-input probes may ask for failure explicitly
        if request.get("input", {}).get("fail") is True:
            sys.stdout.write(
                json.dumps({"id": request["id"], "ok": False,
                            "error": "hook refused"}) + "\\n"
            )
            return 0
        sys.stdout.write(
            json.dumps({"id": request["id"], "ok": True, "result": result}) + "\\n"
        )
        return 0


    if __name__ == "__main__":
        sys.exit(main())
    """
)


@pytest.fixture()
def runner():
    return _unsafe_runner(max_concurrent_runs=8)


def _unsafe_runner(**kwargs):
    return SubprocessAdapterRunner(
        allow_unsafe_local_execution=True,
        **kwargs,
    )


@pytest.fixture()
def adapter(tmp_path):
    """A descriptor + artifact pair: the reference echo adapter."""

    artifact = REFERENCE_ADAPTER.encode("utf-8")
    adapter = build_execution_adapter(
        adapter_id="org.nthdao.test/echo-adapter",
        adapter_version="1.0.0",
        artifact_digest="sha256:" + hashlib.sha256(artifact).hexdigest(),
        execution_modes=["adapter"],
        hooks=[
            {
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }
        ],
        permissions=[],
    )
    return adapter, artifact


def _run(runner, adapter, artifact, *, input_payload=None, **kwargs):
    return runner.run(
        adapter=adapter,
        artifact_bytes=artifact,
        hook_name="fulfillment.deliver",
        hook_version="1",
        rule_id="org.nthdao.test.delivery",
        input_payload=b'{"order": "deliver"}' if input_payload is None else input_payload,
        **kwargs,
    )


class TestProtocolCodec:
    def test_handshake_roundtrip(self):
        line = encode_handshake(artifact_digest="sha256:" + "a" * 64)
        parsed = json.loads(line)
        assert parsed["protocol"] == "nth-trade-adapter-rpc"
        assert parsed["version"] == 1
        parse_handshake_ack(json.dumps({"ok": True}).encode())

    def test_handshake_rejects_bad_ack(self):
        with pytest.raises(AdapterHookRejected, match="handshake"):
            parse_handshake_ack(json.dumps({"ok": False, "error": "x"}).encode())
        with pytest.raises(AdapterHookRejected, match="strict JSON"):
            parse_handshake_ack(b"{nope")

    def test_response_roundtrip(self):
        line = json.dumps({"id": 7, "ok": True, "result": {"status": "ok"}}).encode()
        assert parse_response(line, expected_id=7) == {"status": "ok"}

    def test_response_id_mismatch_rejected(self):
        line = json.dumps({"id": 8, "ok": True, "result": {}}).encode()
        with pytest.raises(AdapterHookRejected, match="id does not match"):
            parse_response(line, expected_id=7)

    def test_boolean_response_id_is_rejected(self):
        line = json.dumps(
            {"id": True, "ok": True, "result": {}}
        ).encode()
        with pytest.raises(AdapterHookRejected, match="id must be an integer"):
            parse_response(line, expected_id=1)

    def test_duplicate_and_unknown_response_fields_are_rejected(self):
        duplicate = b'{"id":7,"id":7,"ok":true,"result":{}}'
        with pytest.raises(AdapterHookRejected, match="duplicate object key"):
            parse_response(duplicate, expected_id=7)
        unknown = b'{"id":7,"ok":true,"result":{},"extra":1}'
        with pytest.raises(AdapterHookRejected, match="unknown fields"):
            parse_response(unknown, expected_id=7)

    def test_response_failure_raises_hook_failed(self):
        line = json.dumps({"id": 7, "ok": False, "error": "boom"}).encode()
        with pytest.raises(AdapterHookFailed, match="boom"):
            parse_response(line, expected_id=7)

    def test_response_without_error_text_rejected(self):
        line = json.dumps({"id": 7, "ok": False}).encode()
        with pytest.raises(AdapterHookRejected, match="needs text"):
            parse_response(line, expected_id=7)

    def test_non_object_response_rejected(self):
        with pytest.raises(AdapterHookRejected, match="JSON object"):
            parse_response(b"[1]", expected_id=7)

    def test_content_descriptor_shape(self):
        descriptor = content_descriptor(b'{"status":"ok"}')
        assert descriptor["media_type"] == "application/json"
        assert descriptor["size_bytes"] == 15
        assert descriptor["digest"].startswith("sha256:")


class TestRunnerHappyPath:
    def test_local_execution_is_disabled_by_default(self, adapter):
        adapter_desc, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="disabled"):
            _run(SubprocessAdapterRunner(), adapter_desc, artifact)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"default_timeout_s": True},
            {"max_timeout_s": float("nan")},
            {"max_concurrent_runs": 0},
            {"max_concurrent_runs": True},
            {"max_result_bytes": 17 * 1024 * 1024},
            {"python": ""},
            {"allow_unsafe_local_execution": "yes"},
        ],
    )
    def test_runner_configuration_is_strict(self, kwargs):
        with pytest.raises((TypeError, ValueError)):
            SubprocessAdapterRunner(**kwargs)

    def test_executes_reference_adapter(self, runner, adapter):
        adapter, artifact = adapter
        outcome = _run(runner, adapter, artifact)
        assert outcome.outcome == "succeeded"
        assert json.loads(outcome.result_payload)["status"] == "ok"
        # the result is content-addressed and resolvable
        descriptor = content_descriptor(outcome.result_payload)
        assert descriptor["size_bytes"] == len(outcome.result_payload)

    def test_result_descriptor_binds_exact_bytes(self, runner, adapter):
        adapter, artifact = adapter
        outcome = _run(runner, adapter, artifact)
        descriptor = content_descriptor(outcome.result_payload)
        assert descriptor["digest"] == content_descriptor(
            outcome.result_payload
        )["digest"]

    def test_input_must_be_json_object(self, runner, adapter):
        adapter, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="JSON object"):
            _run(runner, adapter, artifact, input_payload=b'[1,2]')

    def test_artifact_digest_mismatch_rejected(self, runner, adapter):
        adapter, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="descriptor digest"):
            _run(runner, adapter, artifact + b"\n# tampered")

    def test_unsupported_hook_rejected(self, runner, adapter):
        adapter, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="does not support hook"):
            runner.run(
                adapter=adapter,
                artifact_bytes=artifact,
                hook_name="other.hook",
                hook_version="1",
                rule_id="org.nthdao.test.delivery",
                input_payload=b'{"order": "deliver"}',
            )


class TestRunnerHostility:
    def test_concurrency_limit_fails_closed_without_spawning(self, adapter):
        runner = _unsafe_runner(max_concurrent_runs=1)
        adapter_desc, artifact = adapter
        assert runner._slots.acquire(blocking=False)
        try:
            with pytest.raises(AdapterHookRejected, match="concurrency limit") as info:
                _run(runner, adapter_desc, artifact)
            assert info.value.retryable is True
        finally:
            runner._slots.release()

    def test_timeout_kills_hanging_adapter(self, runner, adapter, tmp_path):
        adapter, _ = adapter
        hang = b"import time; time.sleep(30)"
        hanging = build_execution_adapter(
            adapter_id="org.nthdao.test/hang-adapter",
            adapter_version="1.0.0",
            artifact_digest="sha256:" + __import__("hashlib").sha256(hang).hexdigest(),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=[],
        )
        with pytest.raises(AdapterHookRejected, match="execution budget"):
            _run(runner, hanging, hang, timeout_s=0.5)

    def test_output_flood_bounded(self, adapter):
        flood = (
            b"import sys\n"
            b"import json\n"
            b"sys.stdout.write(json.dumps({'ok': True}) + '\\n')\n"
            b"sys.stdout.write('x' * (64 * 1024 * 1024))\n"
        )
        import hashlib

        from nth_dao.trade_rules.execution_adapter import build_execution_adapter

        flooding = build_execution_adapter(
            adapter_id="org.nthdao.test/flood-adapter",
            adapter_version="1.0.0",
            artifact_digest="sha256:" + hashlib.sha256(flood).hexdigest(),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=[],
        )
        runner = _unsafe_runner()
        with pytest.raises(AdapterHookRejected, match="bound"):
            _run(runner, flooding, flood)

    def test_crashing_adapter_rejected_with_stderr_tail(self, runner, adapter):
        import hashlib

        from nth_dao.trade_rules.execution_adapter import build_execution_adapter

        crash = b"import sys; sys.stderr.write('disk on fire'); sys.exit(3)"
        crashing = build_execution_adapter(
            adapter_id="org.nthdao.test/crash-adapter",
            adapter_version="1.0.0",
            artifact_digest="sha256:" + hashlib.sha256(crash).hexdigest(),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=[],
        )
        with pytest.raises(AdapterHookRejected, match="disk on fire") as info:
            _run(runner, crashing, crash)
        assert info.value.retryable is False

    def test_extra_stdout_lines_rejected(self, adapter):
        import hashlib

        from nth_dao.trade_rules.execution_adapter import build_execution_adapter

        verbose = (
            b"import json, sys\n"
            b"print('banner')\n"
            b"handshake = json.loads(sys.stdin.readline())\n"
            b"print(json.dumps({'ok': True}))\n"
            b"request = json.loads(sys.stdin.readline())\n"
            b"print(json.dumps({'id': request['id'], 'ok': True, 'result': {}}))\n"
        )
        verbose_adapter = build_execution_adapter(
            adapter_id="org.nthdao.test/verbose-adapter",
            adapter_version="1.0.0",
            artifact_digest="sha256:" + hashlib.sha256(verbose).hexdigest(),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=[],
        )
        with pytest.raises(AdapterHookRejected, match="exactly the ack and response"):
            _run(_unsafe_runner(), verbose_adapter, verbose)

    def test_hook_failure_returns_failed_outcome(self, runner, adapter):
        adapter, artifact = adapter
        outcome = _run(runner, adapter, artifact, input_payload=b'{"order": "deliver", "fail": true}')
        assert outcome.outcome == "failed"
        payload = json.loads(outcome.result_payload)
        assert payload == {"error": "hook refused"}

    def test_oversized_input_rejected_before_spawn(self, runner, adapter):
        adapter, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="input payload exceeds"):
            _run(runner, adapter, artifact, input_payload=b'{"x": 1}' * 700_000)

    def test_bad_timeout_rejected(self, runner, adapter):
        adapter, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="timeout_s"):
            _run(runner, adapter, artifact, timeout_s=999)



# ─────────────────── Segment B4: end-to-end with the coordinator ───────────────────


class TestEndToEndWithCoordinator:
    def test_bilateral_order_executes_hook_and_issues_signed_receipt(self, tmp_path):
        """The complete Slice-B story: a bilaterally signed Order whose Rule
        Package declares an adapter-mode Hook; the runtime executes the
        approved artifact; the coordinator issues the signed Execution
        Receipt binding the content-addressed result."""

        sys.path.insert(0, str(Path(__file__).parent))
        from test_trade_rule_agreement import (  # noqa: E402
            _AdapterResolver,
            _digest,
            _execution_receipt,
            _order,
            _setup,
            _utc,
        )

        from nth_dao.spine import SignedEventLog
        from nth_dao.trade_rules import (
            TradeExecutionAdapterPolicy,
            TradeExecutionAuditOutbox,
            TradeExecutionCoordinator,
            TradeExecutionReceiptStore,
        )

        context = _setup(tmp_path, hook_permissions=("network.read",))
        order = _order(context)

        artifact = REFERENCE_ADAPTER.encode("utf-8")
        adapter = build_execution_adapter(
            adapter_id="org.nthdao.test/runtime-echo",
            adapter_version="1.0.0",
            artifact_digest=_digest(artifact),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=["network.read"],
        )
        context["adapter"] = adapter
        context["adapter_resolver"] = _AdapterResolver(
            adapter, artifacts={_digest(artifact): artifact}
        )
        context["adapter_policy"] = TradeExecutionAdapterPolicy(
            accepted_adapter_digests={adapter.digest},
            allowed_execution_modes={"adapter"},
            allowed_permissions={"network.read"},
        )

        # 1. the runtime executes the approved artifact against the input
        runner = _unsafe_runner()
        outcome = runner.run(
            adapter=adapter,
            artifact_bytes=artifact,
            hook_name="fulfillment.deliver",
            hook_version="1",
            rule_id="org.nthdao.test.delivery",
            input_payload=b'{"order": "deliver"}',
        )
        assert outcome.outcome == "succeeded"
        descriptor = content_descriptor(outcome.result_payload)

        # 2. the coordinator notarizes it against the bilateral Order
        coordinator = TradeExecutionCoordinator(
            TradeExecutionReceiptStore(tmp_path / "receipts"),
            TradeExecutionAuditOutbox(tmp_path / "audit"),
            SignedEventLog(tmp_path / "spine.jsonl", context["maker"]),
        )
        receipt = _execution_receipt(
            context,
            order,
            coordinator=coordinator,
            execution_mode="adapter",
            result=descriptor,
            now=_utc("2026-09-01T00:01:00Z"),
        )
        document = receipt.to_dict()
        assert document["outcome"] == "succeeded"
        assert document["result"]["digest"] == descriptor["digest"]
        assert document["adapter"]["adapter_digest"] == adapter.digest
        assert document["adapter"]["execution_mode"] == "adapter"


# ─────────────────── adversarial review round 9 (bugs BB-i / BB-m) ───────────────────


class TestCanonicalContract:
    def test_nan_input_rejected_with_contract_type(self, runner, adapter):
        """Bug BB-i: NaN passes json.loads but is non-portable — must come
        back as AdapterHookRejected, never a raw TypeError."""

        adapter_desc, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="strict JSON"):
            _run(runner, adapter_desc, artifact, input_payload=b'{"x": NaN}')

    def test_duplicate_input_keys_are_rejected(self, runner, adapter):
        adapter_desc, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="duplicate object key"):
            _run(
                runner,
                adapter_desc,
                artifact,
                input_payload=b'{"order":"one","order":"two"}',
            )

    def test_float_result_rejected_with_contract_type(self, tmp_path):
        """Bug BB-m: an adapter returning a float result (or printing NaN)
        must fail closed with the contract type."""

        import hashlib

        from nth_dao.trade_rules.execution_adapter import build_execution_adapter

        artifact = (
            b"import json, sys\n"
            b"sys.stdin.readline()\n"
            b"sys.stdout.write(json.dumps({'ok': True}) + chr(10))\n"
            b"request = json.loads(sys.stdin.readline())\n"
            b"sys.stdout.write(json.dumps({'id': request['id'], 'ok': True,"
            b" 'result': {'price': 1.5}}) + chr(10))\n"
        )
        adapter = build_execution_adapter(
            adapter_id="org.nthdao.test/float-adapter",
            adapter_version="1.0.0",
            artifact_digest="sha256:" + hashlib.sha256(artifact).hexdigest(),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=[],
        )
        with pytest.raises(AdapterHookRejected, match="not canonical JSON"):
            _run(_unsafe_runner(), adapter, artifact, input_payload=b"{}")

    def test_concurrent_runs_are_independent(self, runner, adapter):
        """The runner holds no shared mutable state: eight concurrent runs
        each get their own scratch dir and result."""

        import threading

        adapter_desc, artifact = adapter
        outcomes = []
        errors = []

        def worker(index):
            try:
                outcomes.append(
                    _run(runner, adapter_desc, artifact,
                         input_payload=f'{{"order": "deliver", "n": {index}}}'.encode())
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        assert errors == []
        assert len(outcomes) == 8
        assert all(o.outcome == "succeeded" for o in outcomes)

    def test_crlf_stdout_accepted(self, tmp_path):
        """A Windows-style adapter ending lines with \\r\\n must parse."""

        import hashlib

        from nth_dao.trade_rules.execution_adapter import build_execution_adapter

        artifact = (
            b"import json, sys\n"
            b"sys.stdin.readline()\n"
            b"sys.stdout.write(json.dumps({'ok': True}) + '\\r\\n')\n"
            b"request = json.loads(sys.stdin.readline())\n"
            b"sys.stdout.write(json.dumps({'id': request['id'], 'ok': True,"
            b" 'result': {'status': 'ok'}}) + '\\r\\n')\n"
        )
        adapter = build_execution_adapter(
            adapter_id="org.nthdao.test/crlf-adapter",
            adapter_version="1.0.0",
            artifact_digest="sha256:" + hashlib.sha256(artifact).hexdigest(),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=[],
        )
        outcome = _run(_unsafe_runner(), adapter, artifact, input_payload=b"{}")
        assert outcome.outcome == "succeeded"

    def test_silent_exit_zero_rejected(self, tmp_path):
        """An adapter that exits 0 without emitting the two protocol lines
        fails closed (no phantom success)."""

        import hashlib

        from nth_dao.trade_rules.execution_adapter import build_execution_adapter

        silent = b"pass"
        adapter = build_execution_adapter(
            adapter_id="org.nthdao.test/silent-adapter",
            adapter_version="1.0.0",
            artifact_digest="sha256:" + hashlib.sha256(silent).hexdigest(),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=[],
        )
        with pytest.raises(AdapterHookRejected, match="exactly the ack and response"):
            _run(_unsafe_runner(), adapter, silent, input_payload=b"{}")


# ─────────────────── adversarial review round 10 (BB-n / BB-o) ───────────────────


class TestRetryabilitySemantics:
    def test_missing_interpreter_is_retryable_not_leaked(self, adapter):
        """Bug BB-n: a spawn failure must surface as a retryable
        AdapterHookRejected, never a raw FileNotFoundError."""

        broken = _unsafe_runner(python="/nonexistent/python3")
        adapter_desc, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="could not be started") as info:
            _run(broken, adapter_desc, artifact, input_payload=b"{}")
        assert info.value.retryable is True

    def test_timeout_is_retryable(self, adapter):
        adapter_desc, _ = adapter
        hang = b"import time; time.sleep(30)"
        hanging = build_execution_adapter(
            adapter_id="org.nthdao.test/hang2",
            adapter_version="1.0.0",
            artifact_digest="sha256:" + hashlib.sha256(hang).hexdigest(),
            execution_modes=["adapter"],
            hooks=[{
                "rule_id": "org.nthdao.test.delivery",
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
            permissions=[],
        )
        runner = _unsafe_runner(default_timeout_s=0.3)
        with pytest.raises(AdapterHookRejected, match="execution budget") as info:
            _run(runner, hanging, hang, input_payload=b"{}")
        assert info.value.retryable is True

    def test_permanent_rejections_are_not_retryable(self, runner, adapter):
        adapter_desc, artifact = adapter
        # digest mismatch: the same inputs will fail identically forever
        with pytest.raises(AdapterHookRejected) as info:
            _run(runner, adapter_desc, artifact + b"# tampered",
                 input_payload=b"{}")
        assert info.value.retryable is False
        # protocol violation: same class
        with pytest.raises(AdapterHookRejected) as info2:
            _run(runner, adapter_desc, artifact, input_payload=b"[not-an-object]")
        assert info2.value.retryable is False


class TestScratchCleanup:
    def test_cleanup_failure_is_never_silently_ignored(
        self, monkeypatch, adapter
    ):
        import shutil

        original = shutil.rmtree

        def remove_then_report(path, *, ignore_errors=False):
            original(path, ignore_errors=ignore_errors)
            raise OSError("simulated cleanup report")

        monkeypatch.setattr(
            "nth_dao.trade_rules.adapter_runtime.shutil.rmtree",
            remove_then_report,
        )
        adapter_desc, artifact = adapter
        with pytest.raises(AdapterHookRejected, match="scratch cleanup failed") as info:
            _run(_unsafe_runner(), adapter_desc, artifact)
        assert info.value.retryable is True
