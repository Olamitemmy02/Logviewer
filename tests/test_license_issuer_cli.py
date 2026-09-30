from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from logviewer.licensing.verification import decode_license, verify_license


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ISSUER = PROJECT_ROOT / "tools" / "license_issuer.py"
PRIVATE_KEY = (
    Path.home()
    / ".config"
    / "logviewer"
    / "logviewer_private_key.pem"
)


def _run_issuer(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ISSUER),
            *args,
        ],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
    )


def test_cli_issuer_generates_valid_license(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "customer.license"

    result = _run_issuer(
        "--customer",
        "CLI QA Customer",
        "--edition",
        "PRO",
        "--feature",
        "investigation",
        "--feature",
        "timeline",
        "--feature",
        "findings",
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    assert output.is_file()

    token = output.read_text(encoding="utf-8").strip()

    verification = verify_license(token)

    assert verification.valid is True
    assert verification.license is not None
    assert verification.license.customer == "CLI QA Customer"
    assert verification.license.edition == "PRO"
    assert verification.license.features == (
        "findings",
        "investigation",
        "timeline",
    )

    assert "LogViewer License Created" in result.stdout
    assert "Signature verification: PASSED" in result.stdout


def test_cli_issuer_custom_license_id(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "custom-id.license"

    result = _run_issuer(
        "--customer",
        "Custom ID Customer",
        "--feature",
        "investigation",
        "--license-id",
        "LV-TEST-CUSTOM-16E",
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode == 0, result.stderr

    token = output.read_text(encoding="utf-8").strip()
    verification = verify_license(token)

    assert verification.valid is True
    assert verification.license is not None
    assert verification.license.license_id == "LV-TEST-CUSTOM-16E"


def test_cli_issuer_expiring_license(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "expiring.license"

    from datetime import date, timedelta

    expiration = (
        date.today() + timedelta(days=30)
    ).isoformat()

    result = _run_issuer(
        "--customer",
        "Expiring CLI Customer",
        "--feature",
        "timeline",
        "--expires",
        expiration,
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode == 0, result.stderr

    token = output.read_text(encoding="utf-8").strip()
    verification = verify_license(token)

    assert verification.valid is True
    assert verification.license is not None
    assert verification.license.expires_at == expiration
    assert verification.license.days_remaining == 30


def test_cli_issuer_rejects_past_expiration(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "invalid.license"

    result = _run_issuer(
        "--customer",
        "Invalid Expiration Customer",
        "--feature",
        "investigation",
        "--expires",
        "2000-01-01",
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode != 0
    assert "Expiration date cannot be in the past." in result.stderr
    assert output.exists() is False


def test_cli_issuer_rejects_invalid_expiration_format(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "invalid-format.license"

    result = _run_issuer(
        "--customer",
        "Invalid Date Customer",
        "--feature",
        "investigation",
        "--expires",
        "not-a-date",
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode != 0
    assert "Expiration must use YYYY-MM-DD format." in result.stderr
    assert output.exists() is False


def test_cli_issuer_requires_customer(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "missing-customer.license"

    result = _run_issuer(
        "--feature",
        "investigation",
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode != 0
    assert "required" in result.stderr.lower()
    assert output.exists() is False


def test_cli_issuer_requires_feature(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "missing-feature.license"

    result = _run_issuer(
        "--customer",
        "Missing Feature Customer",
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode != 0
    assert "required" in result.stderr.lower()
    assert output.exists() is False


def test_cli_license_contains_signed_envelope_only(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "envelope.license"

    result = _run_issuer(
        "--customer",
        "Envelope Customer",
        "--feature",
        "investigation",
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode == 0, result.stderr

    token = output.read_text(encoding="utf-8").strip()
    envelope = decode_license(token)

    assert set(envelope.keys()) == {
        "payload",
        "signature",
    }

    payload = envelope["payload"]

    assert payload["customer"] == "Envelope Customer"
    assert payload["edition"] == "PRO"
    assert payload["features"] == ["investigation"]

    serialized = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
    )

    assert "logviewer_private_key.pem" not in serialized
    assert "BEGIN PRIVATE KEY" not in serialized
    assert "BEGIN PRIVATE KEY" not in token


def test_cli_issuer_output_permissions(tmp_path):
    if not PRIVATE_KEY.is_file():
        pytest.skip(
            f"Private signing key is not available at {PRIVATE_KEY}"
        )

    output = tmp_path / "permissions.license"

    result = _run_issuer(
        "--customer",
        "Permission Customer",
        "--feature",
        "investigation",
        "--private-key",
        str(PRIVATE_KEY),
        "--output",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    assert output.is_file()

    mode = output.stat().st_mode & 0o777

    assert mode == 0o600
