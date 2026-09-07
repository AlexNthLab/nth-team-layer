"""Python and independent Node conformance for Intent solver proposal v1."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from nth_dao.plugins.host import InvocationAuthority, PluginAuthorizationError
from nth_dao.plugins.intent_solver import (
    canonical_solver_proposal,
    intent_solver_protocol_digest,
    validate_intent_solver_authority,
    validate_intent_solver_context_binding,
    validate_intent_solver_exchange,
    validate_intent_solver_input,
    validate_intent_solver_output,
)
from nth_dao.plugins.schema import PluginSchemaError
from tools.generate_intent_solver_vectors import vector_documents


VECTOR_ROOT = Path(__file__).parents[1] / "nth_dao" / "plugins" / "vectors"
VECTOR = VECTOR_ROOT / "intent-solver-wire-cases-v1.json"


def _vectors() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def _authority(document: dict) -> InvocationAuthority:
    return InvocationAuthority(
        principal=document["principal"],
        capability_ids=frozenset(document["capability_ids"]),
        mandate_digest=document["mandate_digest"],
        idempotency_key=document["idempotency_key"],
        resource_ids=frozenset(document["resource_ids"]),
    )


def test_intent_solver_vectors_are_reproducible() -> None:
    generated = vector_documents()
    for name, document in generated.items():
        assert json.loads((VECTOR_ROOT / name).read_text(encoding="utf-8")) == document
    assert _vectors()["protocol_digest"] == intent_solver_protocol_digest()


def test_python_validates_intent_solver_vectors() -> None:
    vectors = _vectors()
    for request in vectors["positive_inputs"]:
        validate_intent_solver_input(request)
    for response in vectors["positive_outputs"]:
        validate_intent_solver_output(response)
    for case in vectors["positive_exchanges"]:
        validate_intent_solver_input(case["request"])
        validate_intent_solver_authority(case["request"], _authority(case["authority"]))
        validate_intent_solver_output(case["response"])
        validate_intent_solver_exchange(case["request"], case["response"])
        validate_intent_solver_context_binding(case["response"], case["context"])
    for case in vectors["negative_inputs"]:
        with pytest.raises(PluginSchemaError):
            validate_intent_solver_input(case["input"])
    for case in vectors["negative_outputs"]:
        with pytest.raises(PluginSchemaError):
            validate_intent_solver_output(case["output"])
    for case in vectors["negative_exchanges"]:
        validate_intent_solver_input(case["request"])
        validate_intent_solver_output(case["response"])
        with pytest.raises(PluginSchemaError):
            validate_intent_solver_exchange(case["request"], case["response"])
    for case in vectors["negative_context_bindings"]:
        validate_intent_solver_output(case["response"])
        with pytest.raises(PluginSchemaError):
            validate_intent_solver_context_binding(case["response"], case["context"])
    for case in vectors["negative_authorities"]:
        validate_intent_solver_input(case["request"])
        with pytest.raises(PluginAuthorizationError):
            validate_intent_solver_authority(case["request"], _authority(case["authority"]))
    for case in vectors["raw_negative_inputs"]:
        with pytest.raises((PluginSchemaError, ValueError)):
            validate_intent_solver_input(json.loads(case["input_json"]))
    for case in vectors["raw_negative_outputs"]:
        with pytest.raises((PluginSchemaError, ValueError)):
            validate_intent_solver_output(json.loads(case["output_json"]))
    for case in vectors["raw_negative_proposals"]:
        with pytest.raises((PluginSchemaError, ValueError)):
            canonical_solver_proposal(case["proposal_json"])


def test_node_independently_validates_intent_solver_vectors() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for independent Intent solver conformance")
    completed = subprocess.run(
        [
            node,
            str(Path(__file__).parent / "conformance/intent_solver.cjs"),
            str(VECTOR),
        ],
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    vectors = _vectors()
    assert json.loads(completed.stdout) == {
        "positive_inputs": len(vectors["positive_inputs"]),
        "positive_outputs": len(vectors["positive_outputs"]),
        "positive_exchanges": len(vectors["positive_exchanges"]),
        "negative_inputs": len(vectors["negative_inputs"]),
        "negative_outputs": len(vectors["negative_outputs"]),
        "negative_exchanges": len(vectors["negative_exchanges"]),
        "negative_contexts": len(vectors["negative_context_bindings"]),
        "negative_authorities": len(vectors["negative_authorities"]),
        "raw_negative_inputs": len(vectors["raw_negative_inputs"]),
        "raw_negative_outputs": len(vectors["raw_negative_outputs"]),
        "raw_negative_proposals": len(vectors["raw_negative_proposals"]),
    }


def test_node_conformance_cli_requires_vector_path() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for independent Intent solver conformance")
    completed = subprocess.run(
        [node, str(Path(__file__).parent / "conformance/intent_solver.cjs")],
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == (
        "usage: node intent_solver.cjs <intent-solver-wire-cases-v1.json>\n"
    )
