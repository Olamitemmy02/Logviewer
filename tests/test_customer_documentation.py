from pathlib import Path
import hashlib
import json


ROOT = Path(__file__).resolve().parents[1]

DOCUMENTS = [
    ROOT / "CHANGELOG.md",
    ROOT / "INSTALL.md",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "CORE.md",
    ROOT / "docs" / "PRO.md",
    ROOT / "docs" / "LICENSE_ACTIVATION.md",
    ROOT / "docs" / "TROUBLESHOOTING.md",
    ROOT / "docs" / "SUPPORT.md",
]

PRO_FEATURES = {
    "investigation",
    "threat_scoring",
    "mitre",
    "false_positive_analysis",
    "process_tree",
    "attack_chain",
    "timeline",
    "findings",
}

CORE_CHECKSUM = (
    "a54059f027419c40d10908f5e7fada596757e2a40810a7646903292254e2d98d"
)

PRO_CHECKSUM = (
    "b4e4024284d74909a827241efda648ddf1b04f76196cb111f12f88d0c959651c"
)


def read_text(path):
    return path.read_text(encoding="utf-8")


def sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def test_all_customer_documents_exist():
    for path in DOCUMENTS:
        assert path.is_file(), f"Missing: {path}"
        assert read_text(path).strip(), f"Empty: {path}"


def test_documentation_index_links_exist():
    content = read_text(ROOT / "docs" / "README.md")

    for link in [
        "../INSTALL.md",
        "CORE.md",
        "PRO.md",
        "LICENSE_ACTIVATION.md",
        "TROUBLESHOOTING.md",
        "SUPPORT.md",
        "../CHANGELOG.md",
    ]:
        assert link in content


def test_core_capabilities_are_documented():
    content = read_text(ROOT / "docs" / "CORE.md").lower()

    for capability in [
        "log viewing",
        "log search",
        "log filtering",
        "live monitoring",
        "statistics",
        "report export",
        "log source discovery",
        "snort alert summary",
        "ioc extraction",
        "security correlation",
        "security analysis",
        "application settings",
        "license management",
    ]:
        assert capability in content


def test_all_pro_feature_ids_are_documented():
    content = read_text(ROOT / "docs" / "PRO.md")

    for feature in PRO_FEATURES:
        assert f"`{feature}`" in content


def test_pro_reporting_and_evidence_are_documented():
    content = read_text(ROOT / "docs" / "PRO.md").lower()

    assert "investigation reporting" in content
    assert "markdown" in content
    assert "json" in content
    assert "evidence packages" in content
    assert "sha-256" in content
    assert "evidence verification" in content


def test_license_lifecycle_is_documented():
    content = read_text(
        ROOT / "docs" / "LICENSE_ACTIVATION.md"
    ).lower()

    for term in [
        "license lifecycle",
        "activation",
        "license status",
        "deactivation",
        "expiration",
        "feature entitlement",
        "private signing key",
    ]:
        assert term in content


def test_all_pro_features_are_documented_for_license_entitlement():
    content = read_text(
        ROOT / "docs" / "LICENSE_ACTIVATION.md"
    )

    for feature in PRO_FEATURES:
        assert f"`{feature}`" in content


def test_troubleshooting_is_documented():
    content = read_text(
        ROOT / "docs" / "TROUBLESHOOTING.md"
    )

    for term in [
        "LogViewer Does Not Start",
        "Permission Denied",
        "Pro Features Are Locked",
        "License Activation Fails",
        "Evidence Package Verification Fails",
        "SUPPORT.md",
    ]:
        assert term in content


def test_support_information_is_documented():
    content = read_text(ROOT / "docs" / "SUPPORT.md")

    assert "olamiogungbamila@gmail.com" in content
    assert "08076431994" in content
    assert "Security Issues" in content
    assert "private signing keys" in content


def test_changelog_documents_release():
    content = read_text(ROOT / "CHANGELOG.md")

    assert "LogViewer 1.0.0" in content
    assert "Commercial Release" in content
    assert "Core" in content
    assert "Pro" in content
    assert "Ed25519" in content
    assert "LogViewer-Core-1.0.0.tar.gz" in content
    assert "LogViewer-Pro-1.0.0.tar.gz" in content


def test_private_signing_material_is_not_documented_as_customer_material():
    for path in DOCUMENTS:
        content = read_text(path).lower()

        assert "logviewer_private_key.pem" not in content
        assert "private_key.pem" not in content
        assert "credentials.json" not in content


def test_release_targets_exist():
    for path in [
        ROOT / "README.md",
        ROOT / "pyproject.toml",
        ROOT / "release" / "release_manifest.json",
        ROOT / "install" / "install_core.py",
        ROOT / "install" / "install_pro.py",
    ]:
        assert path.exists(), f"Missing release target: {path}"


def test_release_manifest_matches_documented_pro_features():
    manifest = json.loads(
        read_text(ROOT / "release" / "release_manifest.json")
    )

    assert manifest["product"]["name"] == "LogViewer"
    assert manifest["product"]["release_track"] == "commercial"
    assert manifest["product"]["architecture"] == "core_plus_pro"
    assert set(manifest["pro"]["feature_ids"]) == PRO_FEATURES


def test_signed_off_release_checksums_are_unchanged():
    core = ROOT / "release" / "dist" / "LogViewer-Core-1.0.0.tar.gz"
    pro = ROOT / "release" / "dist" / "LogViewer-Pro-1.0.0.tar.gz"

    assert core.is_file()
    assert pro.is_file()

    assert sha256(core) == CORE_CHECKSUM
    assert sha256(pro) == PRO_CHECKSUM
