from pathlib import Path

from rich.console import Console

from logviewer.pro.investigation.model import Investigation
from logviewer.pro.investigation.workspace import InvestigationWorkspace
from logviewer.pro.reporting import InvestigationReportExporter


class DummyService:
    def list(self):
        return []

    def get(self, investigation_id):
        return None


def build_investigation() -> Investigation:
    investigation = Investigation(
        investigation_id="INV-WORKSPACE-001",
        title="Workspace Report Test",
        status="open",
        severity="medium",
        confidence=0.9,
    )

    investigation.add_event(
        {
            "event_id": "EVT-001",
            "source": "auth.log",
            "message": "Workspace report event",
        }
    )

    return investigation


def test_workspace_report_methods_import():
    workspace = InvestigationWorkspace(
        service=DummyService(),
        console=Console(),
    )

    assert hasattr(workspace, "_report_menu")
    assert hasattr(workspace, "_report_history")
    assert hasattr(workspace, "_view_report")
    assert hasattr(workspace, "_export_report")
    assert hasattr(workspace, "_export_both_reports")


def test_workspace_builds_report_components():
    workspace = InvestigationWorkspace(
        service=DummyService(),
        console=Console(),
    )

    generator = workspace._build_report_generator()
    exporter = workspace._build_report_exporter()

    assert generator is not None
    assert isinstance(exporter, InvestigationReportExporter)


def test_workspace_exporter_can_manage_investigation_reports(
    tmp_path: Path,
):
    investigation = build_investigation()

    workspace = InvestigationWorkspace(
        service=DummyService(),
        console=Console(),
    )

    exporter = workspace._build_report_exporter()
    exporter.export_all(investigation)

    reports = exporter.list_exports(investigation)

    assert len(reports) == 2
    assert any(path.suffix == ".md" for path in reports)
    assert any(path.suffix == ".json" for path in reports)
