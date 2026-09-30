from __future__ import annotations

from pathlib import Path

from rich.console import Console

from logviewer.licensing.console import LicenseConsole
from logviewer.licensing.license_manager import LicenseManager


def test_license_console_imports():
    assert LicenseConsole is not None


def test_license_console_status_without_license(tmp_path):
    manager = LicenseManager(
        license_path=tmp_path / "license.key",
    )

    console = Console(
        record=True,
        width=120,
    )

    workflow = LicenseConsole(
        manager=manager,
        console=console,
    )

    status = workflow.show_status()

    assert status["valid"] is False
    assert status["license_id"] is None
    assert status["features"] == []

    output = console.export_text()

    assert "License Status" in output
    assert "without an active valid Pro license" in output


def test_license_console_deactivate_without_license(tmp_path):
    manager = LicenseManager(
        license_path=tmp_path / "license.key",
    )

    console = Console(
        record=True,
        width=120,
    )

    workflow = LicenseConsole(
        manager=manager,
        console=console,
    )

    assert workflow.deactivate() is False
    assert manager.license_path.exists() is False


def test_license_console_status_with_real_license(
    tmp_path,
    monkeypatch,
):
    from tools.license_issuer import (
        build_payload,
        encode_signed_license,
        load_private_key,
    )
    from logviewer.licensing.verification import verify_license

    private_key_path = (
        Path.home()
        / ".config"
        / "logviewer"
        / "logviewer_private_key.pem"
    )

    if not private_key_path.is_file():
        import pytest

        pytest.skip(
            f"Private signing key is not available at {private_key_path}"
        )

    private_key = load_private_key(private_key_path)

    payload = build_payload(
        customer="Console Test Customer",
        edition="PRO",
        features=[
            "investigation",
            "timeline",
            "findings",
        ],
        expires_at=None,
        license_id="TEST-CONSOLE-16F",
    )

    token = encode_signed_license(
        payload,
        private_key,
    )

    assert verify_license(token).valid is True

    manager = LicenseManager(
        license_path=tmp_path / "license.key",
    )

    result = manager.install(token)

    assert result.valid is True

    console = Console(
        record=True,
        width=120,
    )

    workflow = LicenseConsole(
        manager=manager,
        console=console,
    )

    status = workflow.show_status()

    assert status["valid"] is True
    assert status["license_id"] == "TEST-CONSOLE-16F"
    assert status["customer"] == "Console Test Customer"
    assert set(status["features"]) == {
        "investigation",
        "timeline",
        "findings",
    }

    output = console.export_text()

    assert "ACTIVE" in output
    assert "Console Test Customer" in output
    assert "TEST-CONSOLE-16F" in output


def test_license_console_activation_with_prompt(
    tmp_path,
    monkeypatch,
):
    from tools.license_issuer import (
        build_payload,
        encode_signed_license,
        load_private_key,
    )

    private_key_path = (
        Path.home()
        / ".config"
        / "logviewer"
        / "logviewer_private_key.pem"
    )

    if not private_key_path.is_file():
        import pytest

        pytest.skip(
            f"Private signing key is not available at {private_key_path}"
        )

    private_key = load_private_key(private_key_path)

    payload = build_payload(
        customer="Activation Console Test",
        edition="PRO",
        features=["investigation"],
        expires_at=None,
        license_id="TEST-ACTIVATE-16F",
    )

    token = encode_signed_license(
        payload,
        private_key,
    )

    source_license = tmp_path / "source.license"
    source_license.write_text(
        token + "\n",
        encoding="utf-8",
    )

    manager = LicenseManager(
        license_path=tmp_path / "installed" / "license.key",
    )

    console = Console(
        record=True,
        width=120,
    )

    workflow = LicenseConsole(
        manager=manager,
        console=console,
    )

    monkeypatch.setattr(
        "logviewer.licensing.console.Prompt.ask",
        lambda *args, **kwargs: str(source_license),
    )

    assert workflow.activate() is True

    assert manager.license_path.is_file()
    assert manager.is_activated() is True

    installed = manager.get_license()

    assert installed is not None
    assert installed.license_id == "TEST-ACTIVATE-16F"
    assert installed.customer == "Activation Console Test"


def test_license_console_rejects_missing_source_file(
    tmp_path,
    monkeypatch,
):
    manager = LicenseManager(
        license_path=tmp_path / "license.key",
    )

    console = Console(
        record=True,
        width=120,
    )

    workflow = LicenseConsole(
        manager=manager,
        console=console,
    )

    missing = tmp_path / "does-not-exist.license"

    monkeypatch.setattr(
        "logviewer.licensing.console.Prompt.ask",
        lambda *args, **kwargs: str(missing),
    )

    assert workflow.activate() is False
    assert manager.license_path.exists() is False

    output = console.export_text()

    assert "Activation Failed" in output
    assert "License file was not found" in output


def test_license_console_deactivation_with_confirmation(
    tmp_path,
    monkeypatch,
):
    manager = LicenseManager(
        license_path=tmp_path / "license.key",
    )

    manager.license_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    manager.license_path.write_text(
        "test-license-token\n",
        encoding="utf-8",
    )

    console = Console(
        record=True,
        width=120,
    )

    workflow = LicenseConsole(
        manager=manager,
        console=console,
    )

    monkeypatch.setattr(
        "logviewer.licensing.console.Confirm.ask",
        lambda *args, **kwargs: True,
    )

    assert workflow.deactivate() is True
    assert manager.license_path.exists() is False

    output = console.export_text()

    assert "License Deactivated" in output
