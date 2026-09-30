from pathlib import Path
import sys

import pytest
from rich.console import Console

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Always test the current source tree rather than an older installed package.
sys.path.insert(0, str(PROJECT_ROOT))

import logviewer.menu as menu

from logviewer.licensing.feature_gate import FeatureAccessError, FeatureGate
from logviewer.licensing.license_manager import LicenseManager


def _render_to_text(renderable) -> str:
    console = Console(
        record=True,
        width=160,
        color_system=None,
    )
    console.print(renderable)
    return console.export_text()


def _isolated_unlicensed_gate(tmp_path):
    """
    Build a FeatureGate backed by an isolated license path.

    This deliberately prevents the test from depending on the user's
    real installed LogViewer license.
    """
    license_path = tmp_path / "license.key"

    manager = LicenseManager(
        license_path=license_path,
    )

    return FeatureGate(
        license_manager=manager,
    )


def test_core_menu_contains_all_core_options():
    table = menu._build_core_menu()
    output = _render_to_text(table)

    for option in range(1, 12):
        assert str(option) in output

    expected_labels = [
        "View Logs",
        "Search Logs",
        "Live Monitor",
        "Statistics",
        "Export Reports",
        "Settings",
        "Filters",
        "Snort Alert Summary",
        "Log Sources",
        "Security Correlation",
        "Security Analysis",
    ]

    for label in expected_labels:
        assert label in output


def test_pro_menu_contains_all_pro_options():
    table = menu._build_pro_menu()
    output = _render_to_text(table)

    assert "12" in output
    assert "13" in output
    assert "14" in output

    assert "Pro Investigation" in output
    assert "Investigation Timeline" in output
    assert "Investigation Findings" in output


def test_application_menu_contains_license_about_and_exit():
    table = menu._build_application_menu()
    output = _render_to_text(table)

    assert "15" in output
    assert "16" in output
    assert "0" in output

    assert "License Management" in output
    assert "About" in output
    assert "Exit" in output


def test_application_menu_option_numbers_are_complete_and_unique():
    tables = [
        menu._build_core_menu(),
        menu._build_pro_menu(),
        menu._build_application_menu(),
    ]

    combined = "\n".join(
        _render_to_text(table)
        for table in tables
    )

    for option in range(1, 17):
        assert str(option) in combined

    assert "0" in combined


def test_pro_investigation_dispatch(monkeypatch):
    calls = []

    class FakeService:
        pass

    def fake_workspace(service, console):
        calls.append(
            {
                "service": service,
                "console": console,
            }
        )

    monkeypatch.setattr(
        menu,
        "run_investigation_workspace",
        fake_workspace,
    )

    monkeypatch.setattr(
        "logviewer.pro.investigation.service.InvestigationService",
        FakeService,
    )

    choices = iter(["12", "0"])

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: next(choices),
    )

    monkeypatch.setattr(
        menu,
        "_print_application_header",
        lambda: None,
    )

    monkeypatch.setattr(
        menu,
        "_print_menu_status",
        lambda: None,
    )

    menu.main_menu()

    assert len(calls) == 1
    assert isinstance(calls[0]["service"], FakeService)
    assert calls[0]["console"] is menu.console


def test_timeline_dispatch(monkeypatch):
    calls = []

    monkeypatch.setattr(
        menu,
        "_show_pro_investigation_timeline",
        lambda: calls.append("timeline"),
    )

    choices = iter(["13", "0"])

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: next(choices),
    )

    monkeypatch.setattr(
        menu,
        "_print_application_header",
        lambda: None,
    )

    monkeypatch.setattr(
        menu,
        "_print_menu_status",
        lambda: None,
    )

    menu.main_menu()

    assert calls == ["timeline"]


def test_findings_dispatch(monkeypatch):
    calls = []

    monkeypatch.setattr(
        menu,
        "_show_pro_investigation_findings",
        lambda: calls.append("findings"),
    )

    choices = iter(["14", "0"])

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: next(choices),
    )

    monkeypatch.setattr(
        menu,
        "_print_application_header",
        lambda: None,
    )

    monkeypatch.setattr(
        menu,
        "_print_menu_status",
        lambda: None,
    )

    menu.main_menu()

    assert calls == ["findings"]


def test_license_management_dispatch(monkeypatch):
    calls = []

    monkeypatch.setattr(
        menu,
        "_show_license_management",
        lambda: calls.append("license"),
    )

    choices = iter(["15", "0"])

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: next(choices),
    )

    monkeypatch.setattr(
        menu,
        "_print_application_header",
        lambda: None,
    )

    monkeypatch.setattr(
        menu,
        "_print_menu_status",
        lambda: None,
    )

    menu.main_menu()

    assert calls == ["license"]


def test_about_dispatch(monkeypatch):
    calls = []

    monkeypatch.setattr(
        menu,
        "_show_about",
        lambda: calls.append("about"),
    )

    choices = iter(["16", "0"])

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: next(choices),
    )

    monkeypatch.setattr(
        menu,
        "_print_application_header",
        lambda: None,
    )

    monkeypatch.setattr(
        menu,
        "_print_menu_status",
        lambda: None,
    )

    menu.main_menu()

    assert calls == ["about"]


def test_exit_dispatch_terminates_main_menu(monkeypatch):
    choices = iter(["0"])

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: next(choices),
    )

    monkeypatch.setattr(
        menu,
        "_print_application_header",
        lambda: None,
    )

    monkeypatch.setattr(
        menu,
        "_print_menu_status",
        lambda: None,
    )

    menu.main_menu()


def test_pro_investigation_ui_respects_unlicensed_boundary(
    monkeypatch,
    tmp_path,
):
    gate = _isolated_unlicensed_gate(tmp_path)

    def fake_feature_gate():
        return gate

    monkeypatch.setattr(
        "logviewer.licensing.feature_gate.FeatureGate",
        fake_feature_gate,
    )

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: "",
    )

    menu._show_pro_investigation()

    # The UI should catch FeatureAccessError itself.
    assert gate.check("investigation") is False


def test_timeline_ui_respects_unlicensed_boundary(
    monkeypatch,
    tmp_path,
):
    gate = _isolated_unlicensed_gate(tmp_path)

    def fake_feature_gate():
        return gate

    monkeypatch.setattr(
        "logviewer.licensing.feature_gate.FeatureGate",
        fake_feature_gate,
    )

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: "",
    )

    menu._show_pro_investigation_timeline()

    assert gate.check("investigation") is False


def test_findings_ui_respects_unlicensed_boundary(
    monkeypatch,
    tmp_path,
):
    gate = _isolated_unlicensed_gate(tmp_path)

    def fake_feature_gate():
        return gate

    monkeypatch.setattr(
        "logviewer.licensing.feature_gate.FeatureGate",
        fake_feature_gate,
    )

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: "",
    )

    menu._show_pro_investigation_findings()

    assert gate.check("investigation") is False


def test_main_menu_invalid_option_is_handled(monkeypatch):
    choices = iter(["999", "0"])

    monkeypatch.setattr(
        menu.Prompt,
        "ask",
        lambda *args, **kwargs: next(choices),
    )

    monkeypatch.setattr(
        menu,
        "_print_application_header",
        lambda: None,
    )

    monkeypatch.setattr(
        menu,
        "_print_menu_status",
        lambda: None,
    )

    menu.main_menu()


def test_menu_module_exports_main_menu_only():
    assert hasattr(menu, "main_menu")
    assert menu.__all__ == ["main_menu"]


def test_main_menu_has_all_release_dispatch_options():
    source = Path(menu.__file__).read_text(
        encoding="utf-8"
    )

    for option in range(12, 17):
        assert f'choice == "{option}"' in source

    assert 'choice == "0"' in source

    assert "_show_pro_investigation_timeline()" in source
    assert "_show_pro_investigation_findings()" in source
    assert "_show_license_management()" in source
    assert "_show_about()" in source


def test_application_ui_does_not_require_license_for_menu_rendering():
    core_menu = _render_to_text(
        menu._build_core_menu()
    )

    pro_menu = _render_to_text(
        menu._build_pro_menu()
    )

    application_menu = _render_to_text(
        menu._build_application_menu()
    )

    assert "LOGVIEWER CORE" in core_menu
    assert "LOGVIEWER PRO" in pro_menu
    assert "APPLICATION" in application_menu


@pytest.mark.parametrize(
    "function_name",
    [
        "_build_core_menu",
        "_build_pro_menu",
        "_build_application_menu",
        "_print_application_header",
        "_print_menu_status",
        "_show_license_management",
        "_show_about",
        "_show_pro_investigation",
        "_show_pro_investigation_timeline",
        "_show_pro_investigation_findings",
        "main_menu",
    ],
)
def test_release_ui_symbols_exist(function_name):
    assert hasattr(menu, function_name)
    assert callable(getattr(menu, function_name))


print("16F-D APPLICATION UI RELEASE TESTS LOADED")
