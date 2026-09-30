from __future__ import annotations

import ast
import importlib
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRO_ROOT = PROJECT_ROOT / "logviewer" / "pro"


EXPECTED_PACKAGES = [
    "logviewer.pro",
    "logviewer.pro.investigation",
    "logviewer.pro.timeline",
    "logviewer.pro.findings",
    "logviewer.pro.reporting",
]

REQUIRED_MODULES = [
    "logviewer.pro.investigation.model",
    "logviewer.pro.investigation.engine",
    "logviewer.pro.investigation.service",
    "logviewer.pro.investigation.workspace",
    "logviewer.pro.investigation.display",
    "logviewer.pro.timeline.model",
    "logviewer.pro.timeline.reconstructor",
    "logviewer.pro.findings.analyzer",
    "logviewer.pro.reporting.investigation_report",
    "logviewer.pro.reporting.exporter",
    "logviewer.pro.reporting.evidence_package",
]

FORBIDDEN_IMPORT_ROOTS = {
    "tests",
    "test",
    "demo",
    "demos",
    "example",
    "examples",
}

FORBIDDEN_RELEASE_FILES = {
    ".coverage",
}

FORBIDDEN_RELEASE_SUFFIXES = {
    ".pyc",
    ".pyo",
}


def _python_modules() -> list[str]:
    """Return all real Python modules under logviewer/pro."""
    modules: list[str] = []

    for path in sorted(PRO_ROOT.rglob("*.py")):
        relative = path.relative_to(PROJECT_ROOT).with_suffix("")
        module = ".".join(relative.parts)

        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]

        modules.append(module)

    return modules


def test_pro_root_exists() -> None:
    assert PRO_ROOT.is_dir(), (
        f"Missing Pro package directory: {PRO_ROOT}"
    )


def test_expected_pro_packages_exist() -> None:
    missing = []

    for package in EXPECTED_PACKAGES:
        relative = Path(*package.split("."))
        directory = PROJECT_ROOT / relative

        if not (directory / "__init__.py").exists():
            missing.append(package)

    assert not missing, (
        "Missing Pro packages:\n"
        + "\n".join(missing)
    )


def test_required_pro_modules_exist() -> None:
    missing = []

    for module in REQUIRED_MODULES:
        relative = Path(*module.split("."))
        module_path = PROJECT_ROOT / relative.with_suffix(".py")

        if not module_path.exists():
            missing.append(
                str(module_path.relative_to(PROJECT_ROOT))
            )

    assert not missing, (
        "Missing required Pro modules:\n"
        + "\n".join(missing)
    )


def test_all_required_pro_modules_import_cleanly() -> None:
    failures = []

    for module in EXPECTED_PACKAGES + REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except Exception as exc:
            failures.append(
                f"{module}: "
                f"{type(exc).__name__}: {exc}"
            )

    assert not failures, (
        "Required Pro import failures detected:\n"
        + "\n".join(failures)
    )


def test_all_discovered_pro_modules_import_cleanly() -> None:
    failures = []

    for module in _python_modules():
        try:
            importlib.import_module(module)
        except Exception as exc:
            failures.append(
                f"{module}: "
                f"{type(exc).__name__}: {exc}"
            )

    assert not failures, (
        "Discovered Pro module import failures detected:\n"
        + "\n".join(failures)
    )


def test_all_pro_python_files_parse() -> None:
    failures = []

    for path in sorted(PRO_ROOT.rglob("*.py")):
        try:
            ast.parse(
                path.read_text(encoding="utf-8"),
                filename=str(path),
            )
        except Exception as exc:
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)}: "
                f"{type(exc).__name__}: {exc}"
            )

    assert not failures, (
        "Pro syntax/AST failures detected:\n"
        + "\n".join(failures)
    )


def test_pro_package_has_no_test_or_demo_dependencies() -> None:
    violations = []

    for path in sorted(PRO_ROOT.rglob("*.py")):
        tree = ast.parse(
            path.read_text(encoding="utf-8"),
            filename=str(path),
        )

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names = [
                    alias.name
                    for alias in node.names
                ]

                for name in imported_names:
                    root = name.split(".")[0]

                    if root in FORBIDDEN_IMPORT_ROOTS:
                        violations.append(
                            f"{path.relative_to(PROJECT_ROOT)}: "
                            f"import {name}"
                        )

            elif isinstance(node, ast.ImportFrom):
                if not node.module:
                    continue

                root = node.module.split(".")[0]

                if root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(
                        f"{path.relative_to(PROJECT_ROOT)}: "
                        f"from {node.module} import ..."
                    )

    assert not violations, (
        "Pro package contains test/demo/example dependencies:\n"
        + "\n".join(violations)
    )


def test_pro_package_has_no_release_junk_files() -> None:
    artifacts = []

    for path in PRO_ROOT.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(PROJECT_ROOT)

        # Python normally creates .pyc files inside __pycache__.
        # Those runtime caches are not release artifacts and must not
        # cause this release audit to fail.
        if "__pycache__" in path.parts:
            continue

        if path.name in FORBIDDEN_RELEASE_FILES:
            artifacts.append(str(relative))
            continue

        if path.suffix.lower() in FORBIDDEN_RELEASE_SUFFIXES:
            artifacts.append(str(relative))

    assert not artifacts, (
        "Release junk files found inside Pro package:\n"
        + "\n".join(artifacts)
    )


def test_pro_package_has_python_source() -> None:
    python_files = sorted(PRO_ROOT.rglob("*.py"))

    assert python_files, (
        "No Python source files found in Pro package."
    )


def test_pro_package_inventory_printed(capsys) -> None:
    python_files = sorted(PRO_ROOT.rglob("*.py"))

    print("")
    print("=" * 72)
    print("16F-A: PRO PACKAGE INVENTORY")
    print("=" * 72)
    print(f"Pro root: {PRO_ROOT}")
    print(f"Python source files: {len(python_files)}")
    print("")

    for path in python_files:
        print(
            f"  ✓ "
            f"{path.relative_to(PROJECT_ROOT)}"
        )

    print("")
    print("Required package imports:")

    for package in EXPECTED_PACKAGES:
        print(f"  ✓ {package}")

    print("")
    print("Required module imports:")

    for module in REQUIRED_MODULES:
        print(f"  ✓ {module}")

    print("")
    print("Discovered module count:")
    print(f"  ✓ {len(_python_modules())} modules")

    print("=" * 72)

    captured = capsys.readouterr()

    assert "16F-A: PRO PACKAGE INVENTORY" in captured.out
    assert "Pro root:" in captured.out
    assert "Required package imports:" in captured.out
    assert "Required module imports:" in captured.out
