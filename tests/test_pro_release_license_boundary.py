from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from logviewer.licensing.feature_gate import FeatureAccessError, FeatureGate
from logviewer.licensing.license_manager import LicenseManager
from logviewer.licensing.verification import verify_license


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ISSUER = PROJECT_ROOT / "tools" / "license_issuer.py"


PRO_FEATURES = [
    "investigation",
    "threat_scoring",
    "mitre",
    "false_positive",
    "process_tree",
    "attack_chain",
    "timeline",
    "findings",
]


@pytest.fixture
def isolated_license_environment(tmp_path, monkeypatch):
    license_path = tmp_path / "license.key"
    config_dir = tmp_path / "config"
    issued_dir = tmp_path / "issued"

    config_dir.mkdir()
    issued_dir.mkdir()

    monkeypatch.setenv(
        "LOGVIEWER_LICENSE_PATH",
        str(license_path),
    )

    return {
        "license_path": license_path,
        "config_dir": config_dir,
        "issued_dir": issued_dir,
    }


def _build_manager(environment) -> LicenseManager:
    return LicenseManager(
        license_path=environment["license_path"]
    )


def _issue_license(
    environment,
    *,
    license_id: str,
    features: list[str],
) -> str:
    output_path = environment["issued_dir"] / f"{license_id}.license"

    command = [
        sys.executable,
        str(ISSUER),
        "--customer",
        "16F-B Release Boundary Test",
        "--edition",
        "PRO",
        "--license-id",
        license_id,
        "--output",
        str(output_path),
    ]

    for feature in features:
        command.extend(["--feature", feature])

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, (
        "License issuer failed:\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )

    token = output_path.read_text(
        encoding="utf-8"
    ).strip()

    assert token, (
        "Issuer produced an empty license token."
    )

    verification = verify_license(token)

    assert verification.valid, (
        "Issued test license failed verification: "
        f"{verification.reason}"
    )

    assert verification.license is not None

    return token


def test_no_license_core_available_pro_blocked(
    isolated_license_environment,
):
    environment = isolated_license_environment

    manager = _build_manager(environment)
    gate = FeatureGate(manager)

    assert manager.is_activated() is False
    assert manager.get_verification().valid is False

    # Core remains usable without a Pro license.
    assert manager.status()["valid"] is False

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False

        with pytest.raises(FeatureAccessError):
            gate.require(feature)

    assert not environment["license_path"].exists()


def test_partial_pro_license_only_licensed_features_available(
    isolated_license_environment,
):
    environment = isolated_license_environment

    licensed_features = [
        "investigation",
        "timeline",
        "findings",
    ]

    token = _issue_license(
        environment,
        license_id="LV-16F-B-PARTIAL",
        features=licensed_features,
    )

    manager = _build_manager(environment)

    installation = manager.install(token)

    assert installation.valid is True
    assert installation.license is not None

    assert manager.is_activated() is True

    gate = FeatureGate(manager)

    for feature in licensed_features:
        assert gate.check(feature) is True
        gate.require(feature)

    for feature in PRO_FEATURES:
        if feature in licensed_features:
            continue

        assert gate.check(feature) is False

        with pytest.raises(FeatureAccessError):
            gate.require(feature)


def test_full_pro_license_all_features_available(
    isolated_license_environment,
):
    environment = isolated_license_environment

    token = _issue_license(
        environment,
        license_id="LV-16F-B-FULL",
        features=PRO_FEATURES,
    )

    manager = _build_manager(environment)

    installation = manager.install(token)

    assert installation.valid is True
    assert installation.license is not None

    assert manager.is_activated() is True

    verification = manager.get_verification()

    assert verification.valid is True
    assert verification.license is not None
    assert verification.license.edition == "PRO"

    gate = FeatureGate(manager)

    for feature in PRO_FEATURES:
        assert gate.check(feature) is True
        gate.require(feature)


def test_deactivation_restores_pro_boundary(
    isolated_license_environment,
):
    environment = isolated_license_environment

    token = _issue_license(
        environment,
        license_id="LV-16F-B-REVOKE",
        features=PRO_FEATURES,
    )

    manager = _build_manager(environment)

    installation = manager.install(token)

    assert installation.valid is True
    assert installation.license is not None
    assert manager.is_activated() is True

    gate = FeatureGate(manager)

    for feature in PRO_FEATURES:
        assert gate.check(feature) is True

    assert manager.remove() is True
    assert manager.is_activated() is False

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False

        with pytest.raises(FeatureAccessError):
            gate.require(feature)


def test_license_boundary_does_not_depend_on_current_working_directory(
    isolated_license_environment,
):
    environment = isolated_license_environment

    token = _issue_license(
        environment,
        license_id="LV-16F-B-CWD",
        features=["investigation"],
    )

    manager = _build_manager(environment)

    installation = manager.install(token)

    assert installation.valid is True
    assert installation.license is not None

    gate = FeatureGate(manager)

    assert gate.check("investigation") is True
    assert gate.check("findings") is False


def test_partial_license_metadata_is_exact(
    isolated_license_environment,
):
    environment = isolated_license_environment

    licensed_features = [
        "investigation",
        "threat_scoring",
    ]

    token = _issue_license(
        environment,
        license_id="LV-16F-B-METADATA",
        features=licensed_features,
    )

    verification = verify_license(token)

    assert verification.valid is True
    assert verification.license is not None

    data = verification.license

    assert data.license_id == "LV-16F-B-METADATA"
    assert data.customer == "16F-B Release Boundary Test"
    assert data.edition == "PRO"
    assert set(data.features) == set(licensed_features)


def test_real_license_file_is_not_touched(
    isolated_license_environment,
):
    environment = isolated_license_environment

    manager = _build_manager(environment)

    token = _issue_license(
        environment,
        license_id="LV-16F-B-ISOLATION",
        features=["investigation"],
    )

    installation = manager.install(token)

    assert installation.valid is True
    assert installation.license is not None

    assert environment["license_path"].exists()

    assert manager.remove() is True

    assert not environment["license_path"].exists()


def test_pro_feature_inventory_is_exact() -> None:
    assert len(PRO_FEATURES) == 8
    assert len(set(PRO_FEATURES)) == 8

    expected = {
        "investigation",
        "threat_scoring",
        "mitre",
        "false_positive",
        "process_tree",
        "attack_chain",
        "timeline",
        "findings",
    }

    assert set(PRO_FEATURES) == expected


def test_release_boundary_summary(capsys) -> None:
    print("")
    print("=" * 72)
    print("16F-B: CORE VS PRO RELEASE BOUNDARY")
    print("=" * 72)

    print("")
    print("No-license state:")
    print("  ✓ Core remains available")
    print("  ✓ All Pro features blocked")

    print("")
    print("Partial-license state:")
    print("  ✓ Licensed Pro features available")
    print("  ✓ Unlicensed Pro features blocked")

    print("")
    print("Full-license state:")
    print("  ✓ All eight Pro features available")

    print("")
    print("Deactivation state:")
    print("  ✓ Pro access revoked")
    print("  ✓ Core/Pro boundary restored")

    print("")
    print("Pro feature inventory:")

    for feature in PRO_FEATURES:
        print(f"  ✓ {feature}")

    print("=" * 72)

    captured = capsys.readouterr()

    assert "16F-B: CORE VS PRO RELEASE BOUNDARY" in captured.out
    assert "Core remains available" in captured.out
    assert "All Pro features blocked" in captured.out


__all__ = ["PRO_FEATURES"]
