from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALL_DIR = PROJECT_ROOT / "install"
DIST_DIR = PROJECT_ROOT / "release" / "dist"

CORE_INSTALLER = INSTALL_DIR / "install_core.py"
PRO_INSTALLER = INSTALL_DIR / "install_pro.py"

CORE_ARCHIVE = DIST_DIR / "LogViewer-Core-1.0.0.tar.gz"
PRO_ARCHIVE = DIST_DIR / "LogViewer-Pro-1.0.0.tar.gz"


FORBIDDEN_NAMES = {
    "logviewer_private_key.pem",
    "private_key.pem",
    "license.key",
    "credentials.json",
}


def archive_names(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as archive:
        return set(archive.getnames())


def test_core_installer_exists_and_is_executable():
    assert CORE_INSTALLER.is_file()
    assert CORE_INSTALLER.stat().st_mode & 0o111


def test_pro_installer_exists_and_is_executable():
    assert PRO_INSTALLER.is_file()
    assert PRO_INSTALLER.stat().st_mode & 0o111


def test_core_installer_defines_expected_release_identity():
    text = CORE_INSTALLER.read_text(encoding="utf-8")

    assert 'PRODUCT = "LogViewer"' in text
    assert 'DISTRIBUTION = "Core"' in text
    assert 'VERSION = "1.0.0"' in text


def test_pro_installer_defines_expected_release_identity():
    text = PRO_INSTALLER.read_text(encoding="utf-8")

    assert 'PRODUCT = "LogViewer"' in text
    assert 'DISTRIBUTION = "Pro"' in text
    assert 'VERSION = "1.0.0"' in text


def test_core_installer_constructs_expected_archive_name():
    text = CORE_INSTALLER.read_text(encoding="utf-8")

    assert 'f"{PRODUCT}-{DISTRIBUTION}-{VERSION}.tar.gz"' in text


def test_pro_installer_constructs_expected_archive_name():
    text = PRO_INSTALLER.read_text(encoding="utf-8")

    assert 'f"{PRODUCT}-{DISTRIBUTION}-{VERSION}.tar.gz"' in text


def test_core_archive_is_valid_for_customer_installation():
    names = archive_names(CORE_ARCHIVE)

    assert any(
        "/logviewer/" in name
        for name in names
    )

    assert not any(
        "/logviewer/pro/" in name
        for name in names
    )


def test_pro_archive_is_valid_for_customer_installation():
    names = archive_names(PRO_ARCHIVE)

    assert any(
        "/logviewer/pro/" in name
        for name in names
    )


def test_core_archive_contains_no_private_material():
    names = archive_names(CORE_ARCHIVE)

    assert not any(
        Path(name).name in FORBIDDEN_NAMES
        for name in names
    )


def test_pro_archive_contains_no_private_material():
    names = archive_names(PRO_ARCHIVE)

    assert not any(
        Path(name).name in FORBIDDEN_NAMES
        for name in names
    )


def test_core_installer_can_validate_existing_archive():
    text = CORE_INSTALLER.read_text(encoding="utf-8")

    assert "validate_archive" in text
    assert "Invalid Core archive" in text
    assert str(CORE_ARCHIVE.name) == (
        f"LogViewer-Core-1.0.0.tar.gz"
    )


def test_pro_installer_can_validate_existing_archive():
    text = PRO_INSTALLER.read_text(encoding="utf-8")

    assert "validate_archive" in text
    assert "Invalid Pro archive" in text
    assert str(PRO_ARCHIVE.name) == (
        f"LogViewer-Pro-1.0.0.tar.gz"
    )


def test_installers_use_python_pip():
    core_text = CORE_INSTALLER.read_text(
        encoding="utf-8"
    )

    pro_text = PRO_INSTALLER.read_text(
        encoding="utf-8"
    )

    assert '"-m"' in core_text
    assert '"pip"' in core_text

    assert '"-m"' in pro_text
    assert '"pip"' in pro_text


def test_installers_use_safe_archive_extraction():
    core_text = CORE_INSTALLER.read_text(
        encoding="utf-8"
    )

    pro_text = PRO_INSTALLER.read_text(
        encoding="utf-8"
    )

    assert 'filter="data"' in core_text
    assert 'filter="data"' in pro_text


def test_core_installer_uses_temporary_extraction():
    text = CORE_INSTALLER.read_text(
        encoding="utf-8"
    )

    assert "TemporaryDirectory" in text
    assert "logviewer-core-install-" in text


def test_pro_installer_uses_temporary_extraction():
    text = PRO_INSTALLER.read_text(
        encoding="utf-8"
    )

    assert "TemporaryDirectory" in text
    assert "logviewer-pro-install-" in text


def test_core_installer_has_failure_handling():
    text = CORE_INSTALLER.read_text(
        encoding="utf-8"
    )

    assert "except Exception as exc:" in text
    assert "Core installation failed" in text


def test_pro_installer_has_failure_handling():
    text = PRO_INSTALLER.read_text(
        encoding="utf-8"
    )

    assert "except Exception as exc:" in text
    assert "Pro installation failed" in text
