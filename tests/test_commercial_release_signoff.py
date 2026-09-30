from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_DIR = ROOT / "release"
DIST_DIR = RELEASE_DIR / "dist"
MANIFEST = RELEASE_DIR / "release_manifest.json"

CORE_ARCHIVE = DIST_DIR / "LogViewer-Core-1.0.0.tar.gz"
PRO_ARCHIVE = DIST_DIR / "LogViewer-Pro-1.0.0.tar.gz"

CORE_INSTALLER = ROOT / "install" / "install_core.py"
PRO_INSTALLER = ROOT / "install" / "install_pro.py"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def members(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as archive:
        return set(archive.getnames())


def relative_members(path: Path) -> set[str]:
    result = set()

    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getnames():
            value = member.replace("\\", "/").lstrip("./").rstrip("/")
            parts = Path(value).parts

            if parts and parts[0].startswith("LogViewer-"):
                value = "/".join(parts[1:])

            if value:
                result.add(value)

    return result


def test_release_manifest_is_valid():
    assert MANIFEST.is_file()

    with MANIFEST.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    assert manifest["manifest_version"] == "1.0"
    assert manifest["product"]["name"] == "LogViewer"
    assert manifest["product"]["release_track"] == "commercial"
    assert manifest["product"]["architecture"] == "core_plus_pro"

    assert manifest["core"]["distribution"] == "free"
    assert manifest["core"]["license_required"] is False

    assert manifest["pro"]["distribution"] == "licensed"
    assert manifest["pro"]["license_required"] is True


def test_release_archives_exist():
    assert CORE_ARCHIVE.is_file()
    assert PRO_ARCHIVE.is_file()


def test_release_archives_are_valid_tarballs():
    for archive in (CORE_ARCHIVE, PRO_ARCHIVE):
        with tarfile.open(archive, "r:gz") as tar:
            assert tar.getmembers()


def test_core_and_pro_are_distinct_artifacts():
    assert sha256(CORE_ARCHIVE) != sha256(PRO_ARCHIVE)


def test_core_excludes_pro():
    core = relative_members(CORE_ARCHIVE)

    assert not any(
        path.startswith("logviewer/pro/")
        for path in core
    )


def test_pro_contains_pro():
    pro = relative_members(PRO_ARCHIVE)

    assert any(
        path.startswith("logviewer/pro/")
        for path in pro
    )


def test_pro_contains_core_modules():
    core = relative_members(CORE_ARCHIVE)
    pro = relative_members(PRO_ARCHIVE)

    core_python = {
        path for path in core
        if path.endswith(".py")
    }

    assert core_python <= pro


def test_private_material_is_absent_from_archives():
    forbidden = (
        "logviewer_private_key.pem",
        "private_key.pem",
        "license.key",
        "credentials.json",
    )

    for archive in (CORE_ARCHIVE, PRO_ARCHIVE):
        archive_members = members(archive)

        for member in archive_members:
            lowered = member.lower()

            assert not any(
                marker.lower() in lowered
                for marker in forbidden
            ), f"Private material found: {member}"


def test_runtime_and_test_data_are_absent_from_archives():
    forbidden_parts = {
        ".git",
        ".github",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "tests",
        "exports",
        "logs",
    }

    for archive in (CORE_ARCHIVE, PRO_ARCHIVE):
        archive_members = members(archive)

        for member in archive_members:
            parts = Path(member).parts

            assert not any(
                part in forbidden_parts
                for part in parts
            ), f"Excluded content found: {member}"


def test_installers_are_valid_python():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "py_compile",
            str(CORE_INSTALLER),
            str(PRO_INSTALLER),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"Installer compilation failed:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_core_installer_identity():
    text = CORE_INSTALLER.read_text(encoding="utf-8")

    assert 'PRODUCT = "LogViewer"' in text
    assert 'DISTRIBUTION = "Core"' in text
    assert 'VERSION = "1.0.0"' in text


def test_pro_installer_identity():
    text = PRO_INSTALLER.read_text(encoding="utf-8")

    assert 'PRODUCT = "LogViewer"' in text
    assert 'DISTRIBUTION = "Pro"' in text
    assert 'VERSION = "1.0.0"' in text


def test_release_checksums_are_sha256():
    assert len(sha256(CORE_ARCHIVE)) == 64
    assert len(sha256(PRO_ARCHIVE)) == 64


def test_release_artifact_directory_is_present():
    assert RELEASE_DIR.is_dir()
    assert DIST_DIR.is_dir()
    assert MANIFEST.is_file()


def test_release_identity_matches_expected_version():
    assert CORE_ARCHIVE.name == "LogViewer-Core-1.0.0.tar.gz"
    assert PRO_ARCHIVE.name == "LogViewer-Pro-1.0.0.tar.gz"


def test_release_manifest_defines_all_pro_features():
    with MANIFEST.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    expected = {
        "investigation",
        "threat_scoring",
        "mitre",
        "false_positive_analysis",
        "process_tree",
        "attack_chain",
        "timeline",
        "findings",
    }

    assert set(manifest["pro"]["feature_ids"]) == expected


def test_project_tree_has_no_private_signing_key():
    forbidden = {
        "logviewer_private_key.pem",
        "private_key.pem",
        "signing_key.pem",
    }

    for name in forbidden:
        matches = list(ROOT.rglob(name))

        filtered = [
            path
            for path in matches
            if ".git" not in path.parts
            and "__pycache__" not in path.parts
        ]

        assert not filtered, (
            f"Private signing material found in project tree: "
            f"{filtered}"
        )


def test_pyproject_exists():
    assert (ROOT / "pyproject.toml").is_file()


def test_readme_exists():
    assert (ROOT / "README.md").is_file()


def test_license_exists():
    assert (ROOT / "LICENSE").is_file()


def test_release_manifest_is_recorded_as_artifact():
    with MANIFEST.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    assert "release/release_manifest.json" in (
        manifest["release_artifacts"]
    )


def test_core_and_pro_archive_names_are_unique():
    assert CORE_ARCHIVE.name != PRO_ARCHIVE.name


def test_release_artifacts_have_nonzero_size():
    assert CORE_ARCHIVE.stat().st_size > 0
    assert PRO_ARCHIVE.stat().st_size > 0


def test_release_archives_have_expected_top_level_directories():
    core = members(CORE_ARCHIVE)
    pro = members(PRO_ARCHIVE)

    assert any(
        member.startswith("LogViewer-Core-1.0.0/")
        for member in core
    )

    assert any(
        member.startswith("LogViewer-Pro-1.0.0/")
        for member in pro
    )
