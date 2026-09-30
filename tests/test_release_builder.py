from __future__ import annotations

import json
import tarfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RELEASE_DIR = PROJECT_ROOT / "release"
DIST_DIR = RELEASE_DIR / "dist"
MANIFEST_PATH = RELEASE_DIR / "release_manifest.json"


def load_manifest() -> dict:
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def archive_names(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as archive:
        return set(archive.getnames())


def test_builder_exists():
    builder = RELEASE_DIR / "build_release.py"

    assert builder.is_file()
    assert builder.stat().st_mode & 0o111


def test_manifest_is_available():
    manifest = load_manifest()

    assert manifest["product"]["name"] == "LogViewer"
    assert manifest["manifest_version"] == "1.0"


def test_core_archive_exists():
    archive = DIST_DIR / "LogViewer-Core-1.0.0.tar.gz"

    assert archive.is_file()
    assert archive.stat().st_size > 0


def test_pro_archive_exists():
    archive = DIST_DIR / "LogViewer-Pro-1.0.0.tar.gz"

    assert archive.is_file()
    assert archive.stat().st_size > 0


def test_core_archive_excludes_pro():
    archive = DIST_DIR / "LogViewer-Core-1.0.0.tar.gz"
    names = archive_names(archive)

    assert not any("/logviewer/pro/" in name for name in names)
    assert not any(name.endswith("/logviewer/pro") for name in names)


def test_pro_archive_contains_pro():
    archive = DIST_DIR / "LogViewer-Pro-1.0.0.tar.gz"
    names = archive_names(archive)

    assert any("/logviewer/pro/" in name for name in names)


def test_both_archives_contain_common_release_files():
    for distribution in ("Core", "Pro"):
        archive = DIST_DIR / f"LogViewer-{distribution}-1.0.0.tar.gz"
        names = archive_names(archive)

        root = f"LogViewer-{distribution}-1.0.0"

        assert f"{root}/pyproject.toml" in names
        assert f"{root}/README.md" in names
        assert f"{root}/LICENSE" in names
        assert f"{root}/release_metadata.json" in names


def test_no_private_material_in_archives():
    forbidden = {
        "logviewer_private_key.pem",
        "private_key.pem",
        "license.key",
        "credentials.json",
    }

    for archive in DIST_DIR.glob("*.tar.gz"):
        names = archive_names(archive)

        for name in names:
            assert Path(name).name not in forbidden


def test_no_runtime_or_test_directories_in_archives():
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

    for archive in DIST_DIR.glob("*.tar.gz"):
        names = archive_names(archive)

        for name in names:
            parts = Path(name).parts
            assert not any(part in forbidden_parts for part in parts)


def test_core_metadata_declares_free_distribution():
    archive = DIST_DIR / "LogViewer-Core-1.0.0.tar.gz"

    with tarfile.open(archive, "r:gz") as archive_file:
        member = archive_file.extractfile(
            "LogViewer-Core-1.0.0/release_metadata.json"
        )

        assert member is not None

        metadata = json.loads(member.read().decode("utf-8"))

    assert metadata["distribution"] == "core"
    assert metadata["license_model"] == "free_core"


def test_pro_metadata_declares_license_requirement():
    archive = DIST_DIR / "LogViewer-Pro-1.0.0.tar.gz"

    with tarfile.open(archive, "r:gz") as archive_file:
        member = archive_file.extractfile(
            "LogViewer-Pro-1.0.0/release_metadata.json"
        )

        assert member is not None

        metadata = json.loads(member.read().decode("utf-8"))

    assert metadata["distribution"] == "pro"
    assert metadata["license_model"] == "signed_license_required"
