from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from logviewer.licensing.feature_gate import (
    FeatureAccessError,
    FeatureGate,
)
from logviewer.licensing.license_manager import LicenseManager
from logviewer.licensing.verification import verify_license
from tools.license_issuer import (
    build_payload,
    encode_signed_license,
    load_private_key,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_KEY_PATH = (
    Path.home()
    / ".config"
    / "logviewer"
    / "logviewer_private_key.pem"
)

PRO_FEATURES = (
    "investigation",
    "threat_scoring",
    "mitre",
    "false_positive",
    "process_tree",
    "attack_chain",
    "timeline",
    "findings",
)


def _private_key():
    if not PRIVATE_KEY_PATH.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY_PATH}"
        )
    return load_private_key(PRIVATE_KEY_PATH)


def _create_token(
    *,
    customer: str,
    features: list[str],
    expires_at: str | None = None,
) -> str:
    payload = build_payload(
        customer=customer,
        edition="PRO",
        features=features,
        expires_at=expires_at,
        license_id="TEST-16D-REAL",
    )
    return encode_signed_license(payload, _private_key())


def test_real_issued_license_self_verifies():
    token = _create_token(
        customer="LogViewer 16D Test",
        features=list(PRO_FEATURES),
    )

    result = verify_license(token)

    assert result.valid is True
    assert result.license is not None
    assert result.license.customer == "LogViewer 16D Test"
    assert result.license.edition == "PRO"

    for feature in PRO_FEATURES:
        assert result.license.has_feature(feature) is True


def test_real_license_manager_install_and_verification(tmp_path):
    license_path = tmp_path / "license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="LicenseManager 16D Test",
        features=list(PRO_FEATURES),
    )

    assert manager.is_activated() is False

    result = manager.install(token)

    assert result.valid is True
    assert license_path.is_file()

    verification = manager.get_verification()

    assert verification.valid is True
    assert verification.license is not None
    assert verification.license.customer == "LicenseManager 16D Test"
    assert verification.license.edition == "PRO"

    license_data = manager.get_license()

    assert license_data is not None
    assert license_data.license_id == "TEST-16D-REAL"

    status = manager.status()

    assert status["valid"] is True
    assert status["customer"] == "LicenseManager 16D Test"
    assert status["edition"] == "PRO"
    assert set(status["features"]) == set(PRO_FEATURES)


def test_real_feature_gate_allows_all_licensed_pro_features(tmp_path):
    license_path = tmp_path / "license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="FeatureGate 16D Test",
        features=list(PRO_FEATURES),
    )

    result = manager.install(token)

    assert result.valid is True

    gate = FeatureGate(license_manager=manager)

    for feature in PRO_FEATURES:
        assert gate.check(feature) is True
        gate.require(feature)


def test_real_feature_gate_rejects_unlicensed_pro_feature(tmp_path):
    license_path = tmp_path / "license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="Limited License 16D Test",
        features=["investigation"],
    )

    result = manager.install(token)

    assert result.valid is True

    gate = FeatureGate(license_manager=manager)

    assert gate.check("investigation") is True
    gate.require("investigation")

    for feature in PRO_FEATURES:
        if feature == "investigation":
            continue

        assert gate.check(feature) is False

        with pytest.raises(FeatureAccessError):
            gate.require(feature)


def test_real_feature_gate_rejects_without_license(tmp_path):
    license_path = tmp_path / "missing-license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    gate = FeatureGate(license_manager=manager)

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False

        with pytest.raises(FeatureAccessError):
            gate.require(feature)


def test_real_license_expiration_is_enforced(tmp_path):
    license_path = tmp_path / "expired-license.key"

    expired_date = (
        date.today() - timedelta(days=1)
    ).isoformat()

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="Expired License 16D Test",
        features=list(PRO_FEATURES),
        expires_at=expired_date,
    )

    result = verify_license(token)

    assert result.valid is False
    assert result.license is not None
    assert result.license.expired is True
    assert result.reason == "License has expired."

    install_result = manager.install(token)

    assert install_result.valid is False
    assert license_path.exists() is False

    gate = FeatureGate(license_manager=manager)

    for feature in PRO_FEATURES:
        assert gate.check(feature) is False

        with pytest.raises(FeatureAccessError):
            gate.require(feature)


def test_real_license_is_removed_cleanly(tmp_path):
    license_path = tmp_path / "license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="Removal Test 16D",
        features=["investigation"],
    )

    result = manager.install(token)

    assert result.valid is True
    assert license_path.is_file()
    assert manager.is_activated() is True

    assert manager.remove() is True
    assert license_path.exists() is False
    assert manager.is_activated() is False

    assert manager.remove() is False


def test_real_license_features_are_normalized(tmp_path):
    license_path = tmp_path / "license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="Feature Normalization 16D",
        features=[
            "timeline",
            "findings",
            "timeline",
            " investigation ",
            "",
        ],
    )

    result = manager.install(token)

    assert result.valid is True
    assert result.license is not None

    assert result.license.features == (
        "findings",
        "investigation",
        "timeline",
    )


def test_real_license_cannot_be_activated_after_tampering(tmp_path):
    license_path = tmp_path / "tampered-license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="Tamper Test 16D",
        features=["investigation"],
    )

    result = manager.install(token)

    assert result.valid is True
    assert manager.is_activated() is True

    original = license_path.read_text(encoding="utf-8")

    tampered = original.replace(
        "Tamper",
        "Tampered",
    )

    if tampered == original:
        tampered = original + "tampered"

    license_path.write_text(
        tampered,
        encoding="utf-8",
    )

    verification = manager.get_verification()

    assert verification.valid is False
    assert manager.is_activated() is False

    gate = FeatureGate(license_manager=manager)

    assert gate.check("investigation") is False

    with pytest.raises(FeatureAccessError):
        gate.require("investigation")


def test_real_license_status_reports_remaining_days(tmp_path):
    license_path = tmp_path / "future-license.key"

    future_date = (
        date.today() + timedelta(days=30)
    ).isoformat()

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="Expiry Status 16D",
        features=["investigation"],
        expires_at=future_date,
    )

    result = manager.install(token)

    assert result.valid is True

    status = manager.status()

    assert status["valid"] is True
    assert status["expires_at"] == future_date
    assert status["days_remaining"] == 30


def test_real_pro_license_contains_expected_metadata(tmp_path):
    license_path = tmp_path / "metadata-license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    token = _create_token(
        customer="Metadata Test 16D",
        features=list(PRO_FEATURES),
    )

    result = manager.install(token)

    assert result.valid is True
    assert result.license is not None

    metadata = result.license.metadata

    assert metadata["product"] == "LogViewer"
    assert metadata["license_format"] == 1
    assert metadata["issuer"] == "LogViewer Licensing"


if __name__ == "__main__":
    raise SystemExit(
        pytest.main([__file__, "-q"])
    )
