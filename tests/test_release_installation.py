from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = PROJECT_ROOT / "release" / "dist"

CORE_ARCHIVE = DIST_DIR / "LogViewer-Core-1.0.0.tar.gz"
PRO_ARCHIVE = DIST_DIR / "LogViewer-Pro-1.0.0.tar.gz"


def extract_archive(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(destination, filter="data")

    extracted = [
        path
        for path in destination.iterdir()
        if path.is_dir()
    ]

    assert len(extracted) == 1

    return extracted[0]


def run_python(
    code: str,
    cwd: Path,
    *,
    isolated_home: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()

    if isolated_home is not None:
        isolated_home.mkdir(parents=True, exist_ok=True)

        environment["HOME"] = str(isolated_home)
        environment["XDG_CONFIG_HOME"] = str(
            isolated_home / ".config"
        )
        environment["XDG_DATA_HOME"] = str(
            isolated_home / ".local" / "share"
        )

    return subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_core_archive_installs_as_importable_source(tmp_path):
    root = extract_archive(CORE_ARCHIVE, tmp_path)

    result = run_python(
        """
import sys
sys.path.insert(0, ".")

import logviewer

print("CORE_IMPORT_OK")
""",
        root,
    )

    assert result.returncode == 0, result.stderr
    assert "CORE_IMPORT_OK" in result.stdout


def test_core_archive_does_not_contain_pro_package(tmp_path):
    root = extract_archive(CORE_ARCHIVE, tmp_path)

    assert not (root / "logviewer" / "pro").exists()


def test_core_archive_contains_core_runtime_files(tmp_path):
    root = extract_archive(CORE_ARCHIVE, tmp_path)

    required = [
        root / "logviewer" / "__init__.py",
        root / "logviewer" / "menu.py",
        root / "pyproject.toml",
        root / "README.md",
        root / "LICENSE",
        root / "release_metadata.json",
    ]

    for path in required:
        assert path.exists(), f"Missing Core artifact: {path}"


def test_core_metadata_is_free(tmp_path):
    root = extract_archive(CORE_ARCHIVE, tmp_path)

    metadata = json.loads(
        (root / "release_metadata.json").read_text(
            encoding="utf-8"
        )
    )

    assert metadata["product"] == "LogViewer"
    assert metadata["version"] == "1.0.0"
    assert metadata["distribution"] == "core"
    assert metadata["license_model"] == "free_core"


def test_pro_archive_contains_pro_package(tmp_path):
    root = extract_archive(PRO_ARCHIVE, tmp_path)

    pro_path = root / "logviewer" / "pro"

    assert pro_path.is_dir()
    assert (pro_path / "__init__.py").is_file()
    assert (pro_path / "investigation").is_dir()
    assert (pro_path / "reporting").is_dir()
    assert (pro_path / "scoring").is_dir()


def test_pro_archive_is_importable_as_source(tmp_path):
    root = extract_archive(PRO_ARCHIVE, tmp_path)

    result = run_python(
        """
import sys
sys.path.insert(0, ".")

import logviewer
import logviewer.pro
import logviewer.pro.investigation
import logviewer.pro.reporting

print("PRO_IMPORT_OK")
""",
        root,
    )

    assert result.returncode == 0, result.stderr
    assert "PRO_IMPORT_OK" in result.stdout


def test_pro_metadata_requires_signed_license(tmp_path):
    root = extract_archive(PRO_ARCHIVE, tmp_path)

    metadata = json.loads(
        (root / "release_metadata.json").read_text(
            encoding="utf-8"
        )
    )

    assert metadata["product"] == "LogViewer"
    assert metadata["version"] == "1.0.0"
    assert metadata["distribution"] == "pro"
    assert metadata["license_model"] == "signed_license_required"


def test_pro_is_blocked_without_license(tmp_path):
    root = extract_archive(PRO_ARCHIVE, tmp_path)

    isolated_home = tmp_path / "unlicensed-home"

    result = run_python(
        """
import sys
sys.path.insert(0, ".")

from logviewer.licensing.feature_gate import (
    FeatureAccessError,
    FeatureGate,
)

gate = FeatureGate()

try:
    gate.require("investigation")
except FeatureAccessError:
    print("PRO_BLOCKED_NO_LICENSE")
else:
    raise SystemExit(
        "Pro investigation unexpectedly accessible without license"
    )
""",
        root,
        isolated_home=isolated_home,
    )

    assert result.returncode == 0, result.stderr
    assert "PRO_BLOCKED_NO_LICENSE" in result.stdout


def test_core_and_pro_archives_are_distinct(tmp_path):
    core_root = extract_archive(
        CORE_ARCHIVE,
        tmp_path / "core",
    )

    pro_root = extract_archive(
        PRO_ARCHIVE,
        tmp_path / "pro",
    )

    core_files = {
        path.relative_to(core_root)
        for path in core_root.rglob("*")
        if path.is_file()
    }

    pro_files = {
        path.relative_to(pro_root)
        for path in pro_root.rglob("*")
        if path.is_file()
    }

    assert "logviewer/pro/__init__.py" not in {
        str(path) for path in core_files
    }

    assert "logviewer/pro/__init__.py" in {
        str(path) for path in pro_files
    }

    assert len(pro_files) > len(core_files)


def test_archives_contain_no_private_credentials(tmp_path):
    forbidden = {
        "logviewer_private_key.pem",
        "private_key.pem",
        "license.key",
        "credentials.json",
    }

    for archive in (CORE_ARCHIVE, PRO_ARCHIVE):
        root = extract_archive(
            archive,
            tmp_path / archive.stem.replace(".tar", ""),
        )

        for path in root.rglob("*"):
            if path.is_file():
                assert path.name not in forbidden


def test_archives_contain_no_runtime_data(tmp_path):
    forbidden_directories = {
        ".git",
        ".github",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "tests",
        "logs",
        "exports",
    }

    for archive in (CORE_ARCHIVE, PRO_ARCHIVE):
        root = extract_archive(
            archive,
            tmp_path / f"runtime-{archive.stem}",
        )

        for path in root.rglob("*"):
            relative_parts = path.relative_to(root).parts

            assert not any(
                part in forbidden_directories
                for part in relative_parts
            )


def test_core_and_pro_versions_match(tmp_path):
    core_root = extract_archive(
        CORE_ARCHIVE,
        tmp_path / "core",
    )

    pro_root = extract_archive(
        PRO_ARCHIVE,
        tmp_path / "pro",
    )

    core_metadata = json.loads(
        (core_root / "release_metadata.json").read_text(
            encoding="utf-8"
        )
    )

    pro_metadata = json.loads(
        (pro_root / "release_metadata.json").read_text(
            encoding="utf-8"
        )
    )

    assert core_metadata["product"] == "LogViewer"
    assert pro_metadata["product"] == "LogViewer"
    assert core_metadata["version"] == pro_metadata["version"] == "1.0.0"
