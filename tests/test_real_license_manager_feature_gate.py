from __future__ import annotations

from pathlib import Path

import pytest

from logviewer.licensing.feature_gate import (
    FeatureAccessError,
    FeatureGate,
)
from logviewer.licensing.license_manager import LicenseManager


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


def _build_manager(tmp_path: Path) -> LicenseManager:
    license_path = tmp_path / "license.key"
    public_key_path = tmp_path / "public_key.pem"

    return LicenseManager(
        license_path=license_path,
        public_key_path=public_key_path,
    )


def _build_gate(manager: LicenseManager) -> FeatureGate:
    return FeatureGate(license_manager=manager)


def test_real_license_manager_starts_without_installed_license(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)

    verification = manager.get_verification()

    assert verification is not None
    assert verification.valid is False


def test_real_feature_gate_denies_pro_without_license(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)
    gate = _build_gate(manager)

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False


def test_real_feature_gate_blocks_require_without_license(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)
    gate = _build_gate(manager)

    for feature in PRO_FEATURES:
        with pytest.raises(FeatureAccessError):
            gate.require(feature)


def test_feature_gate_keeps_reference_to_real_license_manager(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)
    gate = _build_gate(manager)

    assert gate.license_manager is manager


def test_real_license_manager_reports_invalid_missing_license(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)

    result = manager.get_verification()

    assert result.valid is False


def test_core_behavior_does_not_require_pro_license(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)
    gate = _build_gate(manager)

    assert all(
        gate.check(feature) is False
        for feature in PRO_FEATURES
    )


def test_feature_gate_rejects_unknown_feature_without_license(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)
    gate = _build_gate(manager)

    assert gate.check("definitely_not_a_real_feature") is False


def test_real_license_manager_can_be_constructed_with_isolated_paths(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)

    assert manager.license_path == tmp_path / "license.key"
    assert manager.public_key_path == tmp_path / "public_key.pem"


def test_real_feature_gate_checks_each_requested_feature(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)
    gate = _build_gate(manager)

    results = {
        feature: gate.check(feature)
        for feature in sorted(PRO_FEATURES)
    }

    assert set(results) == PRO_FEATURES
    assert all(value is False for value in results.values())


def test_real_license_manager_invalid_token_does_not_unlock_pro(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)

    manager.license_path.write_text(
        "THIS_IS_NOT_A_VALID_LOGVIEWER_LICENSE",
        encoding="utf-8",
    )

    gate = _build_gate(manager)

    verification = manager.get_verification()

    assert verification.valid is False

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False


def test_invalid_license_blocks_require_for_all_pro_features(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)

    manager.license_path.write_text(
        "THIS_IS_NOT_A_VALID_LOGVIEWER_LICENSE",
        encoding="utf-8",
    )

    gate = _build_gate(manager)

    for feature in PRO_FEATURES:
        with pytest.raises(FeatureAccessError):
            gate.require(feature)


def test_real_feature_gate_uses_real_manager_verification(
    tmp_path: Path,
) -> None:
    manager = _build_manager(tmp_path)
    gate = _build_gate(manager)

    verification = manager.get_verification()

    assert gate.license_manager is manager
    assert verification.valid is False

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False
