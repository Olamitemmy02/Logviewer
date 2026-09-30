import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = PROJECT_ROOT / "release" / "release_manifest.json"


def load_manifest():
    assert MANIFEST_PATH.is_file(), "Release manifest is missing"

    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_release_manifest_is_valid_json():
    manifest = load_manifest()

    assert isinstance(manifest, dict)
    assert manifest["manifest_version"] == "1.0"


def test_product_identity():
    manifest = load_manifest()

    product = manifest["product"]

    assert product["name"] == "LogViewer"
    assert product["release_track"] == "commercial"
    assert product["architecture"] == "core_plus_pro"


def test_core_is_free():
    manifest = load_manifest()

    core = manifest["core"]

    assert core["distribution"] == "free"
    assert core["license_required"] is False


def test_pro_requires_license():
    manifest = load_manifest()

    pro = manifest["pro"]

    assert pro["distribution"] == "licensed"
    assert pro["license_required"] is True


def test_pro_feature_ids_match_feature_gate():
    manifest = load_manifest()

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

    actual = set(manifest["pro"]["feature_ids"])

    assert actual == expected


def test_core_capabilities_are_present():
    manifest = load_manifest()

    expected = {
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

    actual = set(manifest["core"]["capabilities"])

    assert expected.issubset(actual)


def test_pro_capabilities_are_present():
    manifest = load_manifest()

    expected = {
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

    actual = set(manifest["pro"]["capabilities"])

    assert expected.issubset(actual)


def test_pro_package_exists():
    manifest = load_manifest()

    pro_root = PROJECT_ROOT / "logviewer" / "pro"

    assert pro_root.is_dir()
    assert "logviewer.pro" in manifest["production_modules"]["pro"]


def test_private_material_is_explicitly_excluded():
    manifest = load_manifest()

    excluded = set(manifest["private_excluded"])

    required = {
        "logviewer_private_key.pem",
        "private_key.pem",
        "license.key",
        "issued",
        ".logviewer-pro-license-generator",
        "credentials.json",
    }

    assert required.issubset(excluded)


def test_runtime_directories_are_excluded():
    manifest = load_manifest()

    excluded = set(manifest["runtime_excluded"])

    required = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "tests",
        "exports",
        "logs",
    }

    assert required.issubset(excluded)


def test_distribution_policy():
    manifest = load_manifest()

    policy = manifest["distribution_policy"]

    assert policy["core_source"] == "distributable"
    assert policy["pro_source"] == "distributable_but_license_gated"
    assert policy["private_signing_material"] == "never_distribute"
    assert policy["customer_license"] == "issued_separately"
    assert policy["payment_verification"] == "external_to_application"
    assert policy["runtime_entitlement"] == "signed_license"


def test_required_release_artifacts_are_declared():
    manifest = load_manifest()

    artifacts = set(manifest["release_artifacts"])

    assert "pyproject.toml" in artifacts
    assert "README.md" in artifacts
    assert "LICENSE" in artifacts
    assert "release/release_manifest.json" in artifacts


def test_declared_release_manifest_is_inside_project():
    assert MANIFEST_PATH.is_relative_to(PROJECT_ROOT)


print("17A RELEASE MANIFEST TESTS LOADED")
