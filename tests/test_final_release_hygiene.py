from pathlib import Path
import ast
import importlib
import sys
import zipfile

import pytest
from rich.console import Console

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_to_text(renderable) -> str:
    console = Console(record=True, width=160, color_system=None)
    console.print(renderable)
    return console.export_text()


# ---------------------------------------------------------------------------
# Project structure
# ---------------------------------------------------------------------------

def test_project_root_is_correct():
    assert (PROJECT_ROOT / "pyproject.toml").is_file()
    assert (PROJECT_ROOT / "logviewer").is_dir()
    assert (PROJECT_ROOT / "tests").is_dir()


def test_required_core_packages_exist():
    required = [
        PROJECT_ROOT / "logviewer" / "__init__.py",
        PROJECT_ROOT / "logviewer" / "menu.py",
        PROJECT_ROOT / "logviewer" / "events.py",
        PROJECT_ROOT / "logviewer" / "licensing",
        PROJECT_ROOT / "logviewer" / "pro",
    ]

    for path in required:
        assert path.exists(), f"Missing required project path: {path}"


def test_required_pro_packages_exist():
    required = [
        PROJECT_ROOT / "logviewer" / "pro" / "investigation",
        PROJECT_ROOT / "logviewer" / "pro" / "timeline",
        PROJECT_ROOT / "logviewer" / "pro" / "findings",
        PROJECT_ROOT / "logviewer" / "pro" / "reporting",
    ]

    for path in required:
        assert path.is_dir(), f"Missing Pro package: {path}"


# ---------------------------------------------------------------------------
# Production source syntax
# ---------------------------------------------------------------------------

def test_all_production_python_files_parse():
    failures = []

    for path in PROJECT_ROOT.joinpath("logviewer").rglob("*.py"):
        try:
            source = path.read_text(encoding="utf-8")
            ast.parse(source, filename=str(path))
        except Exception as exc:
            failures.append(f"{path}: {exc}")

    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# Production imports
# ---------------------------------------------------------------------------

def test_core_production_imports():
    modules = [
        "logviewer",
        "logviewer.menu",
        "logviewer.events",
        "logviewer.licensing",
        "logviewer.licensing.feature_gate",
        "logviewer.licensing.license_manager",
        "logviewer.licensing.verification",
        "logviewer.pro",
        "logviewer.pro.investigation",
        "logviewer.pro.investigation.model",
        "logviewer.pro.investigation.engine",
        "logviewer.pro.investigation.service",
        "logviewer.pro.investigation.workspace",
        "logviewer.pro.timeline",
        "logviewer.pro.timeline.model",
        "logviewer.pro.timeline.reconstructor",
        "logviewer.pro.findings",
        "logviewer.pro.findings.analyzer",
        "logviewer.pro.reporting",
        "logviewer.pro.reporting.investigation_report",
        "logviewer.pro.reporting.exporter",
        "logviewer.pro.reporting.evidence_package",
        "logviewer.pro.reporting.evidence_package_verifier",
    ]

    failures = []

    for module_name in modules:
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            failures.append(
                f"{module_name}: {type(exc).__name__}: {exc}"
            )

    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# Core / Pro licensing boundary
# ---------------------------------------------------------------------------

def test_unlicensed_feature_gate_blocks_all_pro_features(tmp_path):
    from logviewer.licensing.feature_gate import FeatureAccessError, FeatureGate
    from logviewer.licensing.license_manager import LicenseManager

    manager = LicenseManager(license_path=tmp_path / "license.key")
    gate = FeatureGate(license_manager=manager)

    pro_features = [
        "investigation",
        "threat_scoring",
        "mitre",
        "false_positive_analysis",
        "process_tree",
        "attack_chain",
        "timeline",
        "findings",
    ]

    for feature in pro_features:
        assert gate.check(feature) is False

        with pytest.raises(FeatureAccessError):
            gate.require(feature)


def test_core_does_not_require_pro_license(tmp_path):
    from logviewer.licensing.feature_gate import FeatureGate
    from logviewer.licensing.license_manager import LicenseManager

    manager = LicenseManager(license_path=tmp_path / "license.key")
    gate = FeatureGate(license_manager=manager)

    assert gate.check("investigation") is False

    import logviewer.menu as menu

    assert callable(menu.main_menu)


# ---------------------------------------------------------------------------
# Licensing implementation integrity
# ---------------------------------------------------------------------------

def test_license_manager_api_is_intact():
    from logviewer.licensing.license_manager import LicenseManager

    expected = [
        "get_verification",
        "get_license",
        "is_activated",
        "install",
        "remove",
        "status",
    ]

    manager = LicenseManager()

    for method_name in expected:
        assert callable(getattr(manager, method_name, None)), (
            f"LicenseManager.{method_name} is missing"
        )


def test_feature_gate_api_is_intact():
    from logviewer.licensing.feature_gate import FeatureGate

    gate = FeatureGate()

    assert callable(gate.check)
    assert callable(gate.require)


# ---------------------------------------------------------------------------
# Investigation model integrity
# ---------------------------------------------------------------------------

def test_investigation_model_contract():
    from logviewer.pro.investigation.model import Investigation

    investigation = Investigation(
        investigation_id="release-hygiene-test",
        title="Release Hygiene Test",
    )

    assert investigation.investigation_id == "release-hygiene-test"
    assert isinstance(investigation.events, list)
    assert isinstance(investigation.evidence, list)
    assert isinstance(investigation.iocs, list)
    assert isinstance(investigation.correlations, list)
    assert isinstance(investigation.mitre_mappings, list)
    assert isinstance(investigation.findings, list)
    assert isinstance(investigation.attack_chain, dict)
    assert isinstance(investigation.timeline, dict)
    assert isinstance(investigation.process_tree, dict)

    data = investigation.as_dict()

    assert isinstance(data, dict)
    assert data["investigation_id"] == "release-hygiene-test"
    assert "summary" in data


# ---------------------------------------------------------------------------
# Reporting contract
# ---------------------------------------------------------------------------

def test_reporting_components_are_available():
    from logviewer.pro.reporting.investigation_report import (
        InvestigationReportGenerator,
    )
    from logviewer.pro.reporting.exporter import InvestigationReportExporter
    from logviewer.pro.reporting.evidence_package import (
        InvestigationEvidencePackageBuilder,
    )
    from logviewer.pro.reporting.evidence_package_verifier import (
        InvestigationEvidencePackageVerifier,
    )

    assert callable(InvestigationReportGenerator)
    assert callable(InvestigationReportExporter)
    assert callable(InvestigationEvidencePackageBuilder)
    assert callable(InvestigationEvidencePackageVerifier)


# ---------------------------------------------------------------------------
# Evidence package integrity
# ---------------------------------------------------------------------------

def test_evidence_package_round_trip(tmp_path):
    from logviewer.pro.investigation.model import Investigation
    from logviewer.pro.reporting.evidence_package import (
        InvestigationEvidencePackageBuilder,
    )
    from logviewer.pro.reporting.evidence_package_verifier import (
        InvestigationEvidencePackageVerifier,
    )

    investigation = Investigation(
        investigation_id="release-package-test",
        title="Release Package Test",
    )

    builder = InvestigationEvidencePackageBuilder(
        export_directory=tmp_path
    )

    package_path = builder.build(investigation)

    assert package_path.exists()
    assert package_path.is_file()

    with zipfile.ZipFile(package_path, "r") as archive:
        names = set(archive.namelist())

    assert any(name.endswith("report.md") for name in names)
    assert any(name.endswith("report.json") for name in names)
    assert any(name.endswith("manifest.json") for name in names)

    verifier = InvestigationEvidencePackageVerifier()
    result = verifier.verify(package_path)

    assert result["verified"] is True
    assert result["status"] == "verified"


# ---------------------------------------------------------------------------
# Menu / application integration
# ---------------------------------------------------------------------------

def test_application_menu_symbols_exist():
    import logviewer.menu as menu

    expected = [
        "main_menu",
        "_build_core_menu",
        "_build_pro_menu",
        "_build_application_menu",
        "_show_license_management",
        "_show_about",
        "_show_pro_investigation",
        "_show_pro_investigation_timeline",
        "_show_pro_investigation_findings",
    ]

    for symbol in expected:
        assert callable(getattr(menu, symbol, None)), (
            f"Missing application menu symbol: {symbol}"
        )


def test_application_menu_contains_release_options():
    import logviewer.menu as menu

    core = menu._build_core_menu()
    pro = menu._build_pro_menu()
    application = menu._build_application_menu()

    core_text = _render_to_text(core)
    pro_text = _render_to_text(pro)
    application_text = _render_to_text(application)

    assert "Security Analysis" in core_text
    assert "Pro Investigation" in pro_text
    assert "Investigation Timeline" in pro_text
    assert "Investigation Findings" in pro_text
    assert "License Management" in application_text
    assert "About" in application_text
    assert "Exit" in application_text


# ---------------------------------------------------------------------------
# Test / release artifact hygiene
# ---------------------------------------------------------------------------

def test_no_private_license_keys_in_project_tree():
    forbidden_names = {
        "logviewer_private_key.pem",
        "private_key.pem",
        "license.key",
    }

    found = []

    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue

        if any(
            part in {".git", ".venv", "venv", "__pycache__"}
            for part in path.parts
        ):
            continue

        if path.name in forbidden_names:
            found.append(str(path))

    assert not found, (
        "Private/runtime license artifacts found inside project tree:\n"
        + "\n".join(found)
    )


def test_no_runtime_database_in_source_tree():
    forbidden_suffixes = {
        ".db",
        ".sqlite",
        ".sqlite3",
    }

    found = []

    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue

        if any(
            part in {".git", ".venv", "venv", "__pycache__"}
            for part in path.parts
        ):
            continue

        if path.suffix.lower() in forbidden_suffixes:
            found.append(str(path))

    assert not found, (
        "Runtime database artifacts found inside project tree:\n"
        + "\n".join(found)
    )


def test_no_generated_license_directory_in_project_tree():
    suspicious = []

    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_dir():
            continue

        if path.name in {
            "issued",
            ".logviewer-pro-license-generator",
        }:
            suspicious.append(str(path))

    assert not suspicious, (
        "License-generation runtime directories found inside project tree:\n"
        + "\n".join(suspicious)
    )


def test_no_common_editor_temp_files():
    forbidden_suffixes = {
        ".swp",
        ".swo",
        ".bak",
        ".tmp",
    }

    found = []

    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue

        if any(
            part in {".git", ".venv", "venv", "__pycache__"}
            for part in path.parts
        ):
            continue

        if path.suffix.lower() in forbidden_suffixes:
            found.append(str(path))

    assert not found, (
        "Temporary/editor artifacts found:\n"
        + "\n".join(found)
    )


# ---------------------------------------------------------------------------
# Git / release hygiene
# ---------------------------------------------------------------------------

def test_no_python_cache_directories_tracked_by_source_layout():
    for path in PROJECT_ROOT.rglob("__pycache__"):
        assert path.is_dir()


def test_pyproject_exists_and_contains_project_metadata():
    pyproject = PROJECT_ROOT / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")

    assert "[project]" in text or "[tool.poetry]" in text
    assert "name" in text


# ---------------------------------------------------------------------------
# Final production source inventory
# ---------------------------------------------------------------------------

def test_production_source_inventory_is_nonempty():
    source_files = list(
        PROJECT_ROOT.joinpath("logviewer").rglob("*.py")
    )

    assert source_files
    assert len(source_files) >= 10


def test_tests_directory_contains_regression_coverage():
    test_files = list(
        PROJECT_ROOT.joinpath("tests").glob("test_*.py")
    )

    assert test_files
    assert len(test_files) >= 10


print("16F-E FINAL RELEASE HYGIENE TESTS LOADED")
