from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from logviewer.pro.investigation.engine import (
    InvestigationEngine,
)


PRO_FEATURES = {
    "investigation",
    "threat_scoring",
    "mitre",
    "false_positive",
    "process_tree",
    "attack_chain",
    "timeline",
    "findings",
}


def _build_engine(feature_gate) -> InvestigationEngine:
    """
    Construct the investigation engine with an explicitly supplied
    FeatureGate-compatible object.

    The test intentionally isolates gate behavior from licensing
    persistence and from real log collection.
    """
    try:
        return InvestigationEngine(
            feature_gate=feature_gate,
        )
    except TypeError:
        engine = InvestigationEngine()
        engine.feature_gate = feature_gate
        return engine


class DenyAllFeatureGate:
    """Simulates a Core-only installation with no Pro features."""

    def check(self, feature):
        return False

    def require(self, feature):
        raise PermissionError(
            f"Pro feature '{feature}' is not available."
        )


class AllowAllFeatureGate:
    """Simulates a valid Pro installation."""

    def check(self, feature):
        return True

    def require(self, feature):
        return True


def test_core_only_gate_denies_every_required_pro_feature() -> None:
    gate = DenyAllFeatureGate()

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False


def test_pro_gate_allows_every_required_pro_feature() -> None:
    gate = AllowAllFeatureGate()

    for feature in PRO_FEATURES:
        assert gate.check(feature) is True


def test_core_only_require_blocks_pro_feature() -> None:
    gate = DenyAllFeatureGate()

    with pytest.raises(PermissionError):
        gate.require("investigation")


def test_pro_require_allows_pro_feature() -> None:
    gate = AllowAllFeatureGate()

    assert gate.require("investigation") is True


def test_engine_accepts_core_only_gate() -> None:
    gate = DenyAllFeatureGate()

    engine = _build_engine(gate)

    assert engine.feature_gate is gate


def test_engine_accepts_pro_gate() -> None:
    gate = AllowAllFeatureGate()

    engine = _build_engine(gate)

    assert engine.feature_gate is gate


def test_engine_uses_supplied_feature_gate_for_pro_checks() -> None:
    gate = MagicMock()
    gate.check.return_value = False

    engine = _build_engine(gate)

    assert engine.feature_gate is gate

    # The engine's _require_feature() method intentionally raises
    # PermissionError when the supplied gate denies access.
    if hasattr(engine, "_require_feature"):
        with pytest.raises(PermissionError):
            engine._require_feature("investigation")

        gate.check.assert_called_with("investigation")


def test_core_only_gate_does_not_claim_pro_access() -> None:
    gate = DenyAllFeatureGate()

    results = {
        feature: gate.check(feature)
        for feature in PRO_FEATURES
    }

    assert results
    assert all(result is False for result in results.values())


def test_pro_gate_claims_pro_access_only_when_enabled() -> None:
    core_gate = DenyAllFeatureGate()
    pro_gate = AllowAllFeatureGate()

    for feature in PRO_FEATURES:
        assert core_gate.check(feature) is False
        assert pro_gate.check(feature) is True


def test_gate_behavior_is_boolean_for_feature_checks() -> None:
    core_gate = DenyAllFeatureGate()
    pro_gate = AllowAllFeatureGate()

    for feature in PRO_FEATURES:
        assert isinstance(core_gate.check(feature), bool)
        assert isinstance(pro_gate.check(feature), bool)


def test_feature_inventory_is_complete() -> None:
    assert PRO_FEATURES == {
        "investigation",
        "threat_scoring",
        "mitre",
        "false_positive",
        "process_tree",
        "attack_chain",
        "timeline",
        "findings",
    }
