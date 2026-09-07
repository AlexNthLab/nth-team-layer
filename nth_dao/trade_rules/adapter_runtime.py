"""Adapter runtime — executes an approved Rule Hook artifact (Slice B).

The Trade Rule Protocol v1 intentionally "executes nothing": manifests
declare Hook contracts (name, version, input/output schema digests,
side effects, permissions) and `TradeExecutionCoordinator.issue` notarizes a
result against a bilaterally signed Order. The missing piece — the code that
actually RUNS an approved adapter artifact against an operation input — is
this module.

MCP alignment (borrowed shape, zero dependencies): the wire is the
initialize → call pattern from Model Context Protocol, expressed as
JSON-lines over stdio between the runtime and one subprocess:

    runtime → adapter : {"protocol": "nth-trade-adapter-rpc", "version": 1,
                         "artifact_digest": "sha256:..."}       (handshake)
    adapter → runtime : {"ok": true}                              (ack)
    runtime → adapter : {"id": N, "hook": {...}, "input": {...}}  (request)
    adapter → runtime : {"id": N, "ok": true, "result": {...}}    (response)
                      | {"id": N, "ok": false, "error": "..."}

Authority boundary (design doc §Trade Rule Protocol): the runner is a pure
hook executor. It does NOT decide who may execute — bilateral consent,
readiness, permission scoping, and schema validation live in
`TradeExecutionCoordinator.issue`, which re-validates the input and (for
successful outcomes) the result against the manifest schemas. The local
runner adds a separate process, wall-clock timeout, and bounded stdio around
one approved, digest-pinned artifact. It is not a security sandbox: local
execution is disabled unless the host explicitly opts in.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.trade_rules.execution_adapter import (
    MAX_ADAPTER_ARTIFACT_BYTES,
    TradeExecutionAdapter,
)

logger = logging.getLogger("nth_dao.trade_rules")

ADAPTER_RPC_PROTOCOL = "nth-trade-adapter-rpc"
ADAPTER_RPC_VERSION = 1
MAX_RESULT_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_S = 10.0
MAX_TIMEOUT_S = 60.0
MAX_CONCURRENT_RUNS = 32
MAX_CONFIGURED_IO_BYTES = 16 * 1024 * 1024

OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"


class AdapterHookRejected(ValueError):
    """Raised when an adapter artifact cannot be executed honestly.

    ``retryable`` separates transient infrastructure failures (execution
    budget exceeded, process crash, spawn failure — the same operation may
    succeed on a retry) from permanent rejections (digest mismatch, bounds,
    protocol violations — the same inputs will fail identically forever).
    Callers driving outbox-style retries must consult it.
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class AdapterHookOutcome:
    """One completed hook invocation, ready for `coordinator.issue`."""

    outcome: str
    result_payload: bytes
    request_id: int
    duration_ms: int


def encode_handshake(*, artifact_digest: str) -> bytes:
    """First line sent to the adapter: pins the digest it must assert."""

    line = canonical_json({
        "protocol": ADAPTER_RPC_PROTOCOL,
        "version": ADAPTER_RPC_VERSION,
        "artifact_digest": artifact_digest,
    })
    return line + b"\n"


def encode_request(
    request_id: int,
    *,
    hook_name: str,
    hook_version: str,
    input_payload: bytes,
) -> bytes:
    """Second line: the hook invocation. ``input_payload`` must be JSON."""

    parsed = _strict_json_object(input_payload, what="input payload")
    try:
        # NaN/Infinity inputs pass json.loads but are non-portable: refuse
        # them here with the contract type, not a raw TypeError
        line = canonical_json({
            "id": request_id,
            "hook": {"name": hook_name, "version": hook_version},
            "input": parsed,
        })
    except (TypeError, ValueError, RecursionError) as exc:
        raise AdapterHookRejected(
            f"input payload is not canonical JSON: {exc}"
        ) from exc
    return line + b"\n"


def _strict_json_object(payload: bytes, *, what: str) -> dict:
    def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate object key: {key}")
            result[key] = value
        return result

    def _constant(value: str) -> Any:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise AdapterHookRejected(f"{what} is not strict JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AdapterHookRejected(f"{what} must be a JSON object")
    return parsed


def _parse_json_line(line: bytes, *, what: str) -> dict:
    return _strict_json_object(line, what=f"adapter {what}")


def parse_handshake_ack(line: bytes) -> None:
    """Validate the adapter's handshake acknowledgement."""

    ack = _parse_json_line(line, what="handshake ack")
    if ack != {"ok": True}:
        raise AdapterHookRejected(
            f"adapter handshake rejected: {json.dumps(ack)[:200]}"
        )


def parse_response(line: bytes, *, expected_id: int) -> dict:
    """Validate one hook response line and return the ``result`` object."""

    parsed = _parse_json_line(line, what="response")
    response_id = parsed.get("id")
    if isinstance(response_id, bool) or not isinstance(response_id, int):
        raise AdapterHookRejected("adapter response id must be an integer")
    if response_id != expected_id:
        raise AdapterHookRejected(
            "adapter response id does not match the request"
        )
    if parsed.get("ok") is True:
        if not set(parsed).issubset({"id", "ok", "result"}):
            raise AdapterHookRejected("adapter success response has unknown fields")
        result = parsed.get("result")
        if not isinstance(result, dict):
            raise AdapterHookRejected("adapter response result must be an object")
        return result
    if parsed.get("ok") is False:
        if not set(parsed).issubset({"id", "ok", "error"}):
            raise AdapterHookRejected("adapter error response has unknown fields")
        error = parsed.get("error")
        if not isinstance(error, str) or not error:
            raise AdapterHookRejected("adapter error response needs text")
        raise AdapterHookFailed(error)
    raise AdapterHookRejected("adapter response ok field must be true or false")


class AdapterHookFailed(AdapterHookRejected):
    """The adapter ran but the hook itself reported failure (outcome=failed)."""


def content_descriptor(
    payload: bytes, *, media_type: str = "application/json"
) -> dict[str, Any]:
    """The wire shape every execution input/result uses (digest-addressed)."""

    return {
        "media_type": media_type,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


class SubprocessAdapterRunner:
    """Execute an adapter in an explicitly enabled, unsafe local process.

    A subprocess boundary is operational containment, not a capability
    sandbox. The artifact can access every file, network, and OS capability
    available to the NTH DAO process. Hosts must keep this runner disabled
    for untrusted artifacts and use a separately sandboxed executor instead.
    """

    def __init__(
        self,
        *,
        python: str = sys.executable,
        default_timeout_s: float = DEFAULT_TIMEOUT_S,
        max_timeout_s: float = MAX_TIMEOUT_S,
        max_result_bytes: int = MAX_RESULT_BYTES,
        max_input_bytes: int = MAX_INPUT_BYTES,
        max_concurrent_runs: int = 1,
        allow_unsafe_local_execution: bool = False,
    ) -> None:
        for name, value in (
            ("default_timeout_s", default_timeout_s),
            ("max_timeout_s", max_timeout_s),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                raise TypeError(f"{name} must be a finite number")
        if not 0.1 <= float(default_timeout_s) <= float(max_timeout_s):
            raise ValueError("default_timeout_s must be within [0.1, max_timeout_s]")
        if not 0.1 <= float(max_timeout_s) <= 300.0:
            raise ValueError("max_timeout_s must be within [0.1, 300]")
        for name, value in (
            ("max_result_bytes", max_result_bytes),
            ("max_input_bytes", max_input_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if (
            isinstance(max_concurrent_runs, bool)
            or not isinstance(max_concurrent_runs, int)
            or not 1 <= max_concurrent_runs <= MAX_CONCURRENT_RUNS
        ):
            raise ValueError(
                f"max_concurrent_runs must be within [1, {MAX_CONCURRENT_RUNS}]"
            )
        if not isinstance(allow_unsafe_local_execution, bool):
            raise TypeError("allow_unsafe_local_execution must be a boolean")
        if not isinstance(python, str) or not python or "\x00" in python:
            raise ValueError("python must be a non-empty executable path")
        if (
            max_result_bytes > MAX_CONFIGURED_IO_BYTES
            or max_input_bytes > MAX_CONFIGURED_IO_BYTES
        ):
            raise ValueError(
                f"configured I/O bounds must not exceed {MAX_CONFIGURED_IO_BYTES} bytes"
            )
        self._python = python
        self._default_timeout_s = float(default_timeout_s)
        self._max_timeout_s = float(max_timeout_s)
        self._max_result_bytes = max_result_bytes
        self._max_input_bytes = max_input_bytes
        self._allow_unsafe_local_execution = allow_unsafe_local_execution
        self._slots = threading.BoundedSemaphore(max_concurrent_runs)

    # ─────────────────────── public API ───────────────────────

    def run(
        self,
        *,
        adapter: TradeExecutionAdapter,
        artifact_bytes: bytes,
        hook_name: str,
        hook_version: str,
        rule_id: str,
        input_payload: bytes,
        timeout_s: Optional[float] = None,
    ) -> AdapterHookOutcome:
        """Run only after the host explicitly accepts local-code authority."""

        if not self._allow_unsafe_local_execution:
            raise AdapterHookRejected(
                "unsafe local adapter execution is disabled; use a sandboxed "
                "executor or explicitly set allow_unsafe_local_execution=True"
            )
        if not self._slots.acquire(blocking=False):
            raise AdapterHookRejected(
                "local adapter execution is at its concurrency limit",
                retryable=True,
            )
        try:
            return self._run_enabled(
                adapter=adapter,
                artifact_bytes=artifact_bytes,
                hook_name=hook_name,
                hook_version=hook_version,
                rule_id=rule_id,
                input_payload=input_payload,
                timeout_s=timeout_s,
            )
        finally:
            self._slots.release()

    def _run_enabled(
        self,
        *,
        adapter: TradeExecutionAdapter,
        artifact_bytes: bytes,
        hook_name: str,
        hook_version: str,
        rule_id: str,
        input_payload: bytes,
        timeout_s: Optional[float] = None,
    ) -> AdapterHookOutcome:
        """Execute one hook and return the content-addressed outcome.

        Raises :class:`AdapterHookRejected` for every refusal that means
        "this invocation never ran honestly" (digest mismatch, bounds,
        protocol violations). A hook that RAN and reported failure returns
        ``outcome="failed"`` with a ``{"error": ...}`` payload instead.
        """

        if timeout_s is not None and (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(float(timeout_s))
        ):
            raise AdapterHookRejected("timeout_s must be a finite number")
        timeout = self._default_timeout_s if timeout_s is None else float(timeout_s)
        if not 0.1 <= timeout <= self._max_timeout_s:
            raise AdapterHookRejected(
                f"timeout_s must be within [0.1, {self._max_timeout_s}]"
            )
        if not isinstance(adapter, TradeExecutionAdapter):
            raise AdapterHookRejected("adapter must be a TradeExecutionAdapter")
        if not isinstance(artifact_bytes, bytes):
            raise AdapterHookRejected("artifact_bytes must be bytes")
        if not isinstance(input_payload, bytes):
            raise AdapterHookRejected("input_payload must be bytes")
        self._verify_adapter_support(adapter, hook_name, hook_version, rule_id)
        self._verify_artifact(adapter, artifact_bytes)
        if len(input_payload) > self._max_input_bytes:
            raise AdapterHookRejected(
                f"input payload exceeds {self._max_input_bytes} bytes"
            )

        started_ms = time.monotonic_ns() // 1_000_000
        request_id = int.from_bytes(os.urandom(8), "big") % (2**31)
        stdin_payload = encode_handshake(
            artifact_digest=adapter.to_dict()["artifact_digest"],
        ) + encode_request(
            request_id,
            hook_name=hook_name,
            hook_version=hook_version,
            input_payload=input_payload,
        )

        scratch = tempfile.mkdtemp(prefix="nth-adapter-")
        try:
            artifact_path = os.path.join(scratch, "adapter.py")
            artifact_fd = os.open(
                artifact_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
            with os.fdopen(artifact_fd, "wb") as handle:
                handle.write(artifact_bytes)
            stdout, stderr, returncode = self._communicate(
                [self._python, "-I", artifact_path],
                stdin_payload,
                timeout=timeout,
                cap=self._max_result_bytes + 65_536,
                scratch=scratch,
            )
        finally:
            try:
                shutil.rmtree(scratch, ignore_errors=False)
            except OSError as exc:
                raise AdapterHookRejected(
                    f"adapter scratch cleanup failed: {exc}", retryable=True
                ) from exc
        duration_ms = time.monotonic_ns() // 1_000_000 - started_ms

        lines = [line for line in stdout.split(b"\n") if line.strip()]
        if len(lines) != 2:
            raise AdapterHookRejected(
                f"adapter stdout must hold exactly the ack and response lines, "
                f"got {len(lines)} line(s)"
            )
        parse_handshake_ack(lines[0])
        try:
            result = parse_response(lines[1], expected_id=request_id)
        except AdapterHookFailed as failed:
            return AdapterHookOutcome(
                outcome=OUTCOME_FAILED,
                result_payload=canonical_json(
                    {"error": failed.args[0][:512]}
                ),
                request_id=request_id,
                duration_ms=duration_ms,
            )
        try:
            result_payload = canonical_json(result)
        except (TypeError, ValueError, RecursionError) as exc:
            raise AdapterHookRejected(
                f"adapter result is not canonical JSON: {exc}"
            ) from exc
        if len(result_payload) > self._max_result_bytes:
            raise AdapterHookRejected(
                f"adapter result exceeds {self._max_result_bytes} bytes"
            )
        return AdapterHookOutcome(
            outcome=OUTCOME_SUCCEEDED,
            result_payload=result_payload,
            request_id=request_id,
            duration_ms=duration_ms,
        )

    # ─────────────────────── internals ───────────────────────

    def _verify_adapter_support(
        self,
        adapter: TradeExecutionAdapter,
        hook_name: str,
        hook_version: str,
        rule_id: str,
    ) -> None:
        supported = {
            (hook.get("rule_id"), hook.get("hook_name"), hook.get("hook_version"))
            for hook in adapter.to_dict()["hooks"]
        }
        if (rule_id, hook_name, hook_version) not in supported:
            raise AdapterHookRejected(
                "adapter does not support hook "
                f"{rule_id}/{hook_name}@{hook_version}"
            )

    def _verify_artifact(
        self, adapter: TradeExecutionAdapter, artifact_bytes: bytes
    ) -> None:
        if len(artifact_bytes) > MAX_ADAPTER_ARTIFACT_BYTES:
            raise AdapterHookRejected(
                f"artifact exceeds {MAX_ADAPTER_ARTIFACT_BYTES} bytes"
            )
        actual = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
        declared = adapter.to_dict()["artifact_digest"]
        if actual != declared:
            raise AdapterHookRejected(
                "artifact bytes do not match the adapter descriptor digest"
            )

    def _communicate(
        self,
        argv: list[str],
        stdin_payload: bytes,
        *,
        timeout: float,
        cap: int,
        scratch: str,
    ) -> tuple[bytes, bytes, int]:
        """Run the adapter; return (stdout, stderr, returncode).

        Three bounded pumps (stdin/stdout/stderr) so a hostile artifact that
        never reads stdin or never closes stdout cannot deadlock the runtime,
        and stdout can never buffer beyond ``cap`` — the process is killed
        the moment the bound is crossed.
        """

        minimal_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=scratch,
                env=minimal_env,
                start_new_session=os.name != "nt",
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
            )
        except OSError as exc:
            # spawn failures (missing interpreter, fd/memory exhaustion) are
            # transient infrastructure conditions, not permanent rejections
            raise AdapterHookRejected(
                f"adapter process could not be started: {exc}", retryable=True
            ) from exc
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        exceeded_stream: Optional[str] = None
        killed = False
        state_lock = threading.Lock()

        def _kill() -> None:
            nonlocal killed
            with state_lock:
                if killed:
                    return
                killed = True
            if os.name == "nt":
                taskkill = shutil.which("taskkill")
                if taskkill is not None:
                    try:
                        subprocess.run(  # noqa: S603 - fixed OS utility argv
                            [taskkill, "/PID", str(process.pid), "/T", "/F"],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5.0,
                            check=False,
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        pass
            else:
                try:
                    killpg = getattr(os, "killpg", None)
                    sigkill = getattr(signal, "SIGKILL", signal.SIGTERM)
                    if callable(killpg):
                        killpg(process.pid, sigkill)
                except (OSError, ProcessLookupError):
                    pass
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass

        def _pump(
            pipe, sink: list[bytes], cap_bytes: int, stream_name: str
        ) -> None:
            nonlocal exceeded_stream
            total = 0
            while True:
                chunk = pipe.read(65_536)
                if not chunk:
                    return
                sink.append(chunk)
                total += len(chunk)
                if total > cap_bytes:
                    with state_lock:
                        if exceeded_stream is None:
                            exceeded_stream = stream_name
                    _kill()
                    return

        def _write_stdin() -> None:
            try:
                process.stdin.write(stdin_payload)  # type: ignore[union-attr]
                process.stdin.close()  # type: ignore[union-attr]
            except (BrokenPipeError, OSError):
                pass  # a dying adapter must not kill the runtime

        pumps = [
            threading.Thread(
                target=_pump,
                args=(process.stdout, stdout_chunks, cap, "stdout"),
                daemon=True,
            ),
            threading.Thread(
                target=_pump,
                args=(process.stderr, stderr_chunks, 65_536, "stderr"),
                daemon=True,
            ),
            threading.Thread(target=_write_stdin, daemon=True),
        ]
        for pump in pumps:
            pump.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                logger.error("adapter process tree did not terminate after timeout")
            raise AdapterHookRejected(
                f"adapter exceeded the {timeout}s execution budget",
                retryable=True,
            ) from None
        for pump in pumps:
            pump.join(timeout=5.0)
        if any(pump.is_alive() for pump in pumps):
            _kill()
            for pump in pumps:
                pump.join(timeout=1.0)
            raise AdapterHookRejected(
                "adapter left inherited stdio open after its parent exited",
            )
        if exceeded_stream is not None:
            # the pump killed the process; report the bound, not the signal
            raise AdapterHookRejected(
                f"adapter {exceeded_stream} exceeded its byte bound"
            )
        if process.returncode != 0:
            tail = b"".join(stderr_chunks)[-512:]
            raise AdapterHookRejected(
                f"adapter exited with code {process.returncode}: "
                f"{tail.decode('utf-8', 'replace')}",
            )
        return b"".join(stdout_chunks), b"".join(stderr_chunks), process.returncode


__all__ = [
    "ADAPTER_RPC_PROTOCOL",
    "ADAPTER_RPC_VERSION",
    "AdapterHookFailed",
    "AdapterHookOutcome",
    "AdapterHookRejected",
    "MAX_CONCURRENT_RUNS",
    "MAX_CONFIGURED_IO_BYTES",
    "MAX_INPUT_BYTES",
    "MAX_RESULT_BYTES",
    "OUTCOME_FAILED",
    "OUTCOME_SUCCEEDED",
    "SubprocessAdapterRunner",
    "content_descriptor",
    "encode_handshake",
    "encode_request",
    "parse_handshake_ack",
    "parse_response",
]
