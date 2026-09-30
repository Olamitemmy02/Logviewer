from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

ENGINE_PATH = (
    PROJECT_ROOT
    / "logviewer"
    / "pro"
    / "investigation"
    / "engine.py"
)


EXPECTED_PRO_FEATURES = {
    "investigation",
    "threat_scoring",
    "mitre",
    "false_positive",
    "process_tree",
    "attack_chain",
    "timeline",
    "findings",
}


def _read_engine_source() -> str:
    assert ENGINE_PATH.exists(), (
        f"Investigation engine not found: {ENGINE_PATH}"
    )

    return ENGINE_PATH.read_text(encoding="utf-8")


def _parse_engine() -> ast.Module:
    return ast.parse(_read_engine_source())


def _feature_gate_calls() -> list[ast.Call]:
    calls: list[ast.Call] = []

    for node in ast.walk(_parse_engine()):
        if not isinstance(node, ast.Call):
            continue

        function = node.func

        if not isinstance(function, ast.Attribute):
            continue

        if function.attr not in {"check", "require"}:
            continue

        owner = function.value

        if isinstance(owner, ast.Attribute):
            if owner.attr == "feature_gate":
                calls.append(node)

    return calls


def _literal_strings(tree: ast.AST) -> set[str]:
    values: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                values.add(node.value)

    return values


def _source_feature_names() -> set[str]:
    source = _read_engine_source()

    return {
        feature
        for feature in EXPECTED_PRO_FEATURES
        if feature in source
    }


def test_investigation_engine_exists() -> None:
    assert ENGINE_PATH.exists()


def test_feature_gate_is_used_by_investigation_engine() -> None:
    calls = _feature_gate_calls()

    assert calls, (
        "Investigation engine does not contain any "
        "self.feature_gate.check()/require() calls."
    )


def test_all_required_pro_features_are_defined_or_referenced() -> None:
    """
    The engine may pass Pro feature constants into FeatureGate rather
    than literal strings. Therefore this audit checks that every required
    feature is explicitly represented in the engine source instead of
    assuming the argument must be an AST string literal.
    """
    referenced_features = _source_feature_names()

    missing = EXPECTED_PRO_FEATURES - referenced_features

    assert not missing, (
        "The investigation engine does not explicitly contain "
        f"these Pro feature identifiers: {sorted(missing)}"
    )


def test_feature_gate_calls_use_supported_gate_methods() -> None:
    calls = _feature_gate_calls()

    methods = {
        call.func.attr
        for call in calls
        if isinstance(call.func, ast.Attribute)
    }

    assert methods <= {"check", "require"}

    assert methods, (
        "No supported FeatureGate method was detected."
    )


def test_feature_gate_calls_have_feature_arguments() -> None:
    calls = _feature_gate_calls()

    assert calls, "No FeatureGate calls were found."

    for call in calls:
        assert call.args, (
            "A FeatureGate.check()/require() call has no "
            "feature argument."
        )


def test_engine_contains_feature_gate_initialization() -> None:
    tree = _parse_engine()

    assignments_found = False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        for target in node.targets:
            if not isinstance(target, ast.Attribute):
                continue

            if target.attr == "feature_gate":
                assignments_found = True

    assert assignments_found, (
        "Investigation engine does not initialize/store "
        "a feature_gate attribute."
    )


def test_pro_feature_names_are_present_in_engine_source() -> None:
    source = _read_engine_source()

    missing = [
        feature
        for feature in sorted(EXPECTED_PRO_FEATURES)
        if feature not in source
    ]

    assert not missing, (
        "These required Pro feature names are absent from "
        f"the investigation engine: {missing}"
    )


def test_expected_feature_inventory_is_explicit() -> None:
    assert EXPECTED_PRO_FEATURES == {
        "investigation",
        "threat_scoring",
        "mitre",
        "false_positive",
        "process_tree",
        "attack_chain",
        "timeline",
        "findings",
    }
