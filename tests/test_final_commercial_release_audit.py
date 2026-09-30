from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_DIR = ROOT / "release"
DIST_DIR = RELEASE_DIR / "dist"
MANIFEST_PATH = RELEASE_DIR / "release_manifest.json"

CORE_ARCHIVE = DIST_DIR / "LogViewer-Core-1.0.0.tar.gz"
PRO_ARCHIVE = DIST_DIR / "LogViewer-Pro-1.0.0.tar.gz"

CORE_INSTALLER = ROOT / "install" / "install_core.py"
PRO_INSTALLER = ROOT / "install" / "install_pro.py"

PRIVATE_MARKERS = (
    "logviewer_private_key.pem",
    "private_key.pem",
    "signing_key.pem",
    "license_private_key.pem",
)

EXPECTED_PRO_FEATURES = {
    "investigation",
    "threat_scoring",
    "mitre",
    "false_positive_analysis",
    "process_tree",
    "attack_chain",
    "timeline",
    "findings",
}

EXPECTED_CORE_CAPABILITIES = {
    "log_viewing",
    "log_search",
    "log_filtering",
    "live_monitoring",
    "statistics",
    "report_export",
    "log_source_discovery",
    "snort_alert_summary",
    "ioc_extraction",
    "security_correlation",
    "security_analysis",
    "application_settings",
    "license_management",
}

EXPECTED_PRO_CAPABILITIES = {
    "security_investigations",
    "threat_scoring",
    "mitre_attack_mapping",
    "false_positive_analysis",
    "process_tree_analysis",
    "attack_chain_reconstruction",
    "investigation_timelines",
    "investigation_findings",
    "investigation_reporting",
    "evidence_packages",
    "evidence_package_verification",
}

EXPECTED_RUNTIME_EXCLUSIONS = {
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

EXPECTED_PRIVATE_EXCLUSIONS = {
    "logviewer_private_key.pem",
    "private_key.pem",
    "license.key",
    "issued",
    ".logviewer-pro-license-generator",
    "credentials.json",
}


def _load_manifest() -> dict:
    assert MANIFEST_PATH.is_file(), (
        f"Release manifest missing: {MANIFEST_PATH}"
    )

    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _archive_members(archive: Path) -> list[str]:
    assert archive.is_file(), f"Missing release archive: {archive}"

    with tarfile.open(archive, "r:gz") as tar:
        return tar.getnames()


def _normalise_member(member: str) -> str:
    """
    Convert an archive member into a relative release path.

    Release archives intentionally contain a single top-level directory,
    for example:

        LogViewer-Core-1.0.0/logviewer/events.py

    The audit works against the content below that directory.
    """
    value = member.replace("\\", "/").lstrip("./").rstrip("/")

    parts = Path(value).parts

    if len(parts) <= 1:
        return value

    if parts[0].startswith("LogViewer-"):
        return "/".join(parts[1:])

    return value


def _relative_members(archive: Path) -> set[str]:
    return {
        _normalise_member(member)
        for member in _archive_members(archive)
        if _normalise_member(member)
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _assert_clean_members(members: list[str]) -> None:
    forbidden_runtime_parts = set(
        EXPECTED_RUNTIME_EXCLUSIONS
    )

    for raw_member in members:
        member = raw_member.replace("\\", "/").lstrip("./")
        parts = Path(member).parts

        assert not member.startswith("/"), (
            f"Absolute archive path detected: {member}"
        )

        assert ".." not in parts, (
            f"Path traversal component detected: {member}"
        )

        lower_member = member.lower()

        assert not any(
            marker.lower() in lower_member
            for marker in PRIVATE_MARKERS
        ), (
            f"Private signing material detected: {member}"
        )

        assert not any(
            part in forbidden_runtime_parts
            for part in parts
        ), (
            f"Runtime/cache directory detected: {member}"
        )

        relative = _normalise_member(member)

        assert not relative.startswith("tests/"), (
            f"Test content detected: {member}"
        )

        assert not relative.startswith("test/"), (
            f"Test content detected: {member}"
        )


def test_release_manifest_exists_and_is_valid():
    manifest = _load_manifest()

    assert manifest["manifest_version"] == "1.0"

    product = manifest["product"]

    assert isinstance(product, dict)
    assert product["name"] == "LogViewer"
    assert product["release_track"] == "commercial"
    assert product["architecture"] == "core_plus_pro"
    assert product["description"]


def test_core_distribution_is_free_and_unlicensed():
    manifest = _load_manifest()

    core = manifest["core"]

    assert core["distribution"] == "free"
    assert core["license_required"] is False


def test_pro_distribution_is_licensed():
    manifest = _load_manifest()

    pro = manifest["pro"]

    assert pro["distribution"] == "licensed"
    assert pro["license_required"] is True


def test_release_manifest_defines_expected_pro_features():
    manifest = _load_manifest()

    assert set(manifest["pro"]["feature_ids"]) == (
        EXPECTED_PRO_FEATURES
    )


def test_release_manifest_defines_expected_core_capabilities():
    manifest = _load_manifest()

    assert set(manifest["core"]["capabilities"]) == (
        EXPECTED_CORE_CAPABILITIES
    )


def test_release_manifest_defines_expected_pro_capabilities():
    manifest = _load_manifest()

    assert set(manifest["pro"]["capabilities"]) == (
        EXPECTED_PRO_CAPABILITIES
    )


def test_release_manifest_defines_production_modules():
    manifest = _load_manifest()

    production_modules = manifest["production_modules"]

    assert production_modules["core"] == [
        "logviewer",
        "logviewer.analysis",
        "logviewer.core",
        "logviewer.sources",
        "logviewer.snort",
    ]

    assert production_modules["pro"] == [
        "logviewer.pro",
    ]


def test_release_manifest_defines_runtime_exclusions():
    manifest = _load_manifest()

    assert set(manifest["runtime_excluded"]) == (
        EXPECTED_RUNTIME_EXCLUSIONS
    )


def test_release_manifest_defines_private_exclusions():
    manifest = _load_manifest()

    assert set(manifest["private_excluded"]) == (
        EXPECTED_PRIVATE_EXCLUSIONS
    )


def test_release_manifest_distribution_policy_is_consistent():
    manifest = _load_manifest()

    policy = manifest["distribution_policy"]

    assert policy["core_source"] == "distributable"
    assert policy["pro_source"] == "distributable_but_license_gated"
    assert policy["private_signing_material"] == "never_distribute"
    assert policy["customer_license"] == "issued_separately"
    assert policy["payment_verification"] == "external_to_application"
    assert policy["runtime_entitlement"] == "signed_license"


def test_release_archives_exist():
    assert CORE_ARCHIVE.is_file()
    assert PRO_ARCHIVE.is_file()


def test_archive_versions_match_installer_versions():
    core_text = CORE_INSTALLER.read_text(encoding="utf-8")
    pro_text = PRO_INSTALLER.read_text(encoding="utf-8")

    assert 'VERSION = "1.0.0"' in core_text
    assert 'VERSION = "1.0.0"' in pro_text

    assert CORE_ARCHIVE.name == "LogViewer-Core-1.0.0.tar.gz"
    assert PRO_ARCHIVE.name == "LogViewer-Pro-1.0.0.tar.gz"


def test_core_archive_has_no_pro_source():
    members = _relative_members(CORE_ARCHIVE)

    assert not any(
        member.startswith("logviewer/pro/")
        or member == "logviewer/pro"
        for member in members
    )


def test_pro_archive_contains_pro_source():
    members = _relative_members(PRO_ARCHIVE)

    assert any(
        member.startswith("logviewer/pro/")
        for member in members
    )


def test_core_archive_contains_core_package():
    members = _relative_members(CORE_ARCHIVE)

    assert any(
        member.startswith("logviewer/")
        for member in members
    )

    assert "logviewer/__init__.py" in members


def test_pro_archive_contains_required_pro_modules():
    members = _relative_members(PRO_ARCHIVE)

    required = {
        "logviewer/pro/__init__.py",
        "logviewer/pro/findings/__init__.py",
        "logviewer/pro/investigation/__init__.py",
        "logviewer/pro/reporting/__init__.py",
        "logviewer/pro/timeline/__init__.py",
    }

    missing = required - members

    assert not missing, (
        "Required Pro modules missing from archive: "
        f"{sorted(missing)}"
    )


def test_archives_have_clean_release_contents():
    _assert_clean_members(_archive_members(CORE_ARCHIVE))
    _assert_clean_members(_archive_members(PRO_ARCHIVE))


def test_archive_integrity_is_readable():
    for archive in (CORE_ARCHIVE, PRO_ARCHIVE):
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()

            assert members, f"Archive is empty: {archive}"

            for member in members:
                if member.isfile():
                    extracted = tar.extractfile(member)

                    assert extracted is not None

                    # Read the complete member so corruption is detected.
                    extracted.read()


def test_release_checksums_are_valid():
    core_hash = _sha256(CORE_ARCHIVE)
    pro_hash = _sha256(PRO_ARCHIVE)

    assert len(core_hash) == 64
    assert len(pro_hash) == 64
    assert core_hash != pro_hash


def test_installers_exist_and_compile():
    assert CORE_INSTALLER.is_file()
    assert PRO_INSTALLER.is_file()

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
        "Installer compilation failed:\n"
        f"{result.stdout}\n"
        f"{result.stderr}"
    )


def test_core_installer_is_bound_to_core_distribution():
    text = CORE_INSTALLER.read_text(encoding="utf-8")

    assert 'PRODUCT = "LogViewer"' in text
    assert 'DISTRIBUTION = "Core"' in text
    assert 'VERSION = "1.0.0"' in text
    assert 'f"{PRODUCT}-{DISTRIBUTION}-{VERSION}.tar.gz"' in text


def test_pro_installer_is_bound_to_pro_distribution():
    text = PRO_INSTALLER.read_text(encoding="utf-8")

    assert 'PRODUCT = "LogViewer"' in text
    assert 'DISTRIBUTION = "Pro"' in text
    assert 'VERSION = "1.0.0"' in text
    assert 'f"{PRODUCT}-{DISTRIBUTION}-{VERSION}.tar.gz"' in text


def test_release_manifest_lists_expected_artifacts():
    manifest = _load_manifest()

    artifacts = manifest["release_artifacts"]

    assert isinstance(artifacts, list)

    expected = {
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "release/release_manifest.json",
    }

    assert expected.issubset(set(artifacts))


def test_release_manifest_contains_complete_release_metadata():
    manifest = _load_manifest()

    required = {
        "manifest_version",
        "product",
        "core",
        "pro",
        "production_modules",
        "runtime_excluded",
        "private_excluded",
        "release_artifacts",
        "distribution_policy",
    }

    assert required.issubset(manifest.keys())


def test_pro_archive_contains_core_python_structure():
    core_members = _relative_members(CORE_ARCHIVE)
    pro_members = _relative_members(PRO_ARCHIVE)

    required_core = {
        member
        for member in core_members
        if member.endswith(".py")
    }

    missing_from_pro = required_core - pro_members

    assert not missing_from_pro, (
        "Pro archive is missing Core Python modules: "
        f"{sorted(missing_from_pro)}"
    )


def test_pro_archive_contains_additional_pro_content():
    core_members = _relative_members(CORE_ARCHIVE)
    pro_members = _relative_members(PRO_ARCHIVE)

    additional = pro_members - core_members

    assert additional, (
        "Pro archive does not contain content beyond the Core archive."
    )

    assert any(
        member.startswith("logviewer/pro/")
        for member in additional
    )


def test_current_source_tree_has_no_private_signing_material():
    for marker in PRIVATE_MARKERS:
        matches = list(ROOT.rglob(marker))

        filtered = [
            path
            for path in matches
            if ".git" not in path.parts
            and "__pycache__" not in path.parts
        ]

        assert not filtered, (
            "Private signing material found inside project tree: "
            f"{filtered}"
        )


def test_pro_is_blocked_without_license_in_isolated_environment(tmp_path):
    isolated_home = tmp_path / "home"
    isolated_config = isolated_home / ".config"
    isolated_data = isolated_home / ".local" / "share"

    isolated_config.mkdir(parents=True)
    isolated_data.mkdir(parents=True)

    env = os.environ.copy()
    env["HOME"] = str(isolated_home)
    env["XDG_CONFIG_HOME"] = str(isolated_config)
    env["XDG_DATA_HOME"] = str(isolated_data)
    env["PYTHONPATH"] = str(ROOT)

    code = """
from logviewer.licensing.feature_gate import FeatureAccessError, FeatureGate

gate = FeatureGate()

try:
    gate.require("investigation")
except FeatureAccessError:
    print("PRO BLOCKED WITHOUT LICENSE")
else:
    raise SystemExit(
        "Pro feature unexpectedly accessible without license"
    )
"""

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        "Unlicensed Pro isolation check failed:\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )

    assert "PRO BLOCKED WITHOUT LICENSE" in result.stdout


def test_release_directory_contains_required_artifacts():
    assert RELEASE_DIR.is_dir()
    assert DIST_DIR.is_dir()
    assert MANIFEST_PATH.is_file()
    assert CORE_ARCHIVE.is_file()
    assert PRO_ARCHIVE.is_file()


def test_release_identity_is_consistent():
    manifest = _load_manifest()

    identity = {
        "product": manifest["product"]["name"],
        "release_track": manifest["product"]["release_track"],
        "architecture": manifest["product"]["architecture"],
        "core_archive": {
            "name": CORE_ARCHIVE.name,
            "sha256": _sha256(CORE_ARCHIVE),
        },
        "pro_archive": {
            "name": PRO_ARCHIVE.name,
            "sha256": _sha256(PRO_ARCHIVE),
        },
    }

    assert identity["product"] == "LogViewer"
    assert identity["release_track"] == "commercial"
    assert identity["architecture"] == "core_plus_pro"

    assert identity["core_archive"]["name"] == (
        "LogViewer-Core-1.0.0.tar.gz"
    )
    assert identity["pro_archive"]["name"] == (
        "LogViewer-Pro-1.0.0.tar.gz"
    )

    assert len(identity["core_archive"]["sha256"]) == 64
    assert len(identity["pro_archive"]["sha256"]) == 64
