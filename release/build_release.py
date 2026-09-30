#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RELEASE_DIR = PROJECT_ROOT / "release"
DIST_DIR = RELEASE_DIR / "dist"
MANIFEST_PATH = RELEASE_DIR / "release_manifest.json"

VERSION = "1.0.0"

COMMON_FILES = [
    "pyproject.toml",
    "README.md",
    "LICENSE",
]

CORE_DIRECTORIES = [
    "logviewer",
]

PRO_DIRECTORIES = [
    "logviewer",
]


EXCLUDED_NAMES = {
    ".git",
    ".github",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "tests",
    "exports",
    "logs",
    ".mypy_cache",
    ".ruff_cache",
    ".coverage",
}


EXCLUDED_FILES = {
    "logviewer_private_key.pem",
    "private_key.pem",
    "license.key",
    "credentials.json",
}


def load_manifest() -> dict:
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def should_exclude(path: Path) -> bool:
    relative = path.relative_to(PROJECT_ROOT)

    if any(part in EXCLUDED_NAMES for part in relative.parts):
        return True

    if path.name in EXCLUDED_FILES:
        return True

    if path.suffix in {".pyc", ".pyo"}:
        return True

    return False


def copy_file(source: Path, destination_root: Path) -> None:
    if should_exclude(source):
        return

    relative = source.relative_to(PROJECT_ROOT)
    destination = destination_root / relative

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def copy_tree(source: Path, destination_root: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Required directory not found: {source}")

    for path in source.rglob("*"):
        if path.is_dir():
            continue

        if should_exclude(path):
            continue

        copy_file(path, destination_root)


def copy_common_files(destination_root: Path) -> None:
    for relative_name in COMMON_FILES:
        source = PROJECT_ROOT / relative_name

        if not source.is_file():
            raise FileNotFoundError(
                f"Required release artifact not found: {relative_name}"
            )

        copy_file(source, destination_root)


def copy_core_package(destination_root: Path) -> None:
    source = PROJECT_ROOT / "logviewer"

    for path in source.rglob("*"):
        if path.is_dir():
            continue

        if should_exclude(path):
            continue

        relative = path.relative_to(source)

        if relative.parts and relative.parts[0] == "pro":
            continue

        copy_file(path, destination_root)


def copy_pro_package(destination_root: Path) -> None:
    source = PROJECT_ROOT / "logviewer"

    for path in source.rglob("*"):
        if path.is_dir():
            continue

        if should_exclude(path):
            continue

        copy_file(path, destination_root)


def write_build_metadata(destination_root: Path, distribution: str) -> None:
    metadata = {
        "product": "LogViewer",
        "version": VERSION,
        "distribution": distribution,
        "architecture": "core_plus_pro",
        "source_project": "LogViewer",
        "license_model": (
            "free_core"
            if distribution == "core"
            else "signed_license_required"
        ),
    }

    metadata_path = destination_root / "release_metadata.json"

    with metadata_path.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)
        handle.write("\n")


def validate_no_private_material(root: Path) -> None:
    forbidden_names = EXCLUDED_FILES | {
        "logviewer_private_key.pem",
        "private_key.pem",
    }

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        if path.name in forbidden_names:
            raise RuntimeError(
                f"Private material found in release: {path}"
            )

        if any(part in EXCLUDED_NAMES for part in path.relative_to(root).parts):
            raise RuntimeError(
                f"Excluded directory found in release: {path}"
            )


def validate_core(root: Path) -> None:
    pro_path = root / "logviewer" / "pro"

    if pro_path.exists():
        raise RuntimeError(
            "Core release incorrectly contains logviewer/pro"
        )

    required = [
        root / "logviewer",
        root / "pyproject.toml",
        root / "README.md",
        root / "LICENSE",
        root / "release_metadata.json",
    ]

    for path in required:
        if not path.exists():
            raise RuntimeError(
                f"Core release missing required artifact: {path}"
            )


def validate_pro(root: Path) -> None:
    required = [
        root / "logviewer",
        root / "logviewer" / "pro",
        root / "pyproject.toml",
        root / "README.md",
        root / "LICENSE",
        root / "release_metadata.json",
    ]

    for path in required:
        if not path.exists():
            raise RuntimeError(
                f"Pro release missing required artifact: {path}"
            )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def create_archive(source_root: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(
            source_root,
            arcname=source_root.name,
            recursive=True,
        )


def build_distribution(distribution: str) -> Path:
    with tempfile.TemporaryDirectory(
        prefix=f"logviewer-{distribution}-"
    ) as temporary_directory:

        temporary_root = Path(temporary_directory)

        package_name = f"LogViewer-{distribution.capitalize()}-{VERSION}"
        package_root = temporary_root / package_name
        package_root.mkdir(parents=True, exist_ok=True)

        copy_common_files(package_root)

        if distribution == "core":
            copy_core_package(package_root)
            write_build_metadata(package_root, "core")
            validate_core(package_root)

        elif distribution == "pro":
            copy_pro_package(package_root)
            write_build_metadata(package_root, "pro")
            validate_pro(package_root)

        else:
            raise ValueError(f"Unsupported distribution: {distribution}")

        validate_no_private_material(package_root)

        archive_path = DIST_DIR / f"{package_name}.tar.gz"

        if archive_path.exists():
            archive_path.unlink()

        create_archive(package_root, archive_path)

        return archive_path


def validate_manifest() -> None:
    manifest = load_manifest()

    if manifest.get("manifest_version") != "1.0":
        raise RuntimeError("Unsupported release manifest version")

    if manifest["product"]["name"] != "LogViewer":
        raise RuntimeError("Unexpected product name")

    if manifest["core"]["distribution"] != "free":
        raise RuntimeError("Core distribution must be free")

    if manifest["core"]["license_required"] is not False:
        raise RuntimeError("Core must not require a license")

    if manifest["pro"]["distribution"] != "licensed":
        raise RuntimeError("Pro distribution must be licensed")

    if manifest["pro"]["license_required"] is not True:
        raise RuntimeError("Pro must require a license")

    expected_features = {
        "investigation",
        "threat_scoring",
        "mitre",
        "false_positive_analysis",
        "process_tree",
        "attack_chain",
        "timeline",
        "findings",
    }

    actual_features = set(manifest["pro"]["feature_ids"])

    if actual_features != expected_features:
        raise RuntimeError(
            "Manifest Pro feature IDs do not match the expected feature set"
        )


def main() -> None:
    print("=== LogViewer 17B Release Builder ===")

    validate_manifest()

    DIST_DIR.mkdir(parents=True, exist_ok=True)

    for existing_archive in DIST_DIR.glob("*.tar.gz"):
        existing_archive.unlink()

    core_archive = build_distribution("core")
    pro_archive = build_distribution("pro")

    print()
    print("=== RELEASE ARTIFACTS ===")

    for archive in (core_archive, pro_archive):
        size = archive.stat().st_size
        digest = sha256_file(archive)

        print(f"Name:   {archive.name}")
        print(f"Size:   {size} bytes")
        print(f"SHA256: {digest}")
        print()

    print("17B RELEASE BUILD: PASSED")


if __name__ == "__main__":
    main()
