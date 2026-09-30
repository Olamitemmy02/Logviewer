from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from logviewer.pro.investigation.workspace import InvestigationWorkspace


def _investigation() -> SimpleNamespace:
    return SimpleNamespace(
        investigation_id="TEST-15G",
        title="Workspace Verification Test",
    )


def _workspace() -> InvestigationWorkspace:
    service = object()
    return InvestigationWorkspace(
        service=service,
        console=Console(),
    )


def test_build_evidence_package_verifier_imports() -> None:
    workspace = _workspace()

    verifier = workspace._build_evidence_package_verifier()

    assert verifier is not None
    assert verifier.__class__.__name__ == (
        "InvestigationEvidencePackageVerifier"
    )


def test_verification_package_path_uses_investigation_id(
    monkeypatch,
) -> None:
    workspace = _workspace()
    investigation = _investigation()

    captured = {}

    class FakeVerifier:
        def verify(self, package_path):
            captured["path"] = package_path
            return {
                "status": "verified",
                "verified": True,
                "algorithm": "SHA-256",
                "investigation": {
                    "id": "TEST-15G",
                    "title": "Workspace Verification Test",
                },
                "files": [],
                "errors": [],
                "warnings": [],
                "limitations": [],
            }

    monkeypatch.setattr(
        workspace,
        "_build_evidence_package_verifier",
        lambda: FakeVerifier(),
    )
    monkeypatch.setattr(
        "logviewer.pro.investigation.workspace.Prompt.ask",
        lambda *args, **kwargs: "",
    )

    workspace._verify_evidence_package(investigation)

    assert captured["path"] == Path(
        "exports/investigation_TEST-15G_evidence.zip"
    )


def test_verification_handles_missing_package(
    monkeypatch,
) -> None:
    workspace = _workspace()
    investigation = _investigation()

    captured = {}

    class FakeVerifier:
        def verify(self, package_path):
            captured["path"] = package_path
            return {
                "status": "error",
                "verified": False,
                "algorithm": "SHA-256",
                "investigation": {},
                "files": [],
                "errors": [
                    "Evidence package not found."
                ],
                "warnings": [],
                "limitations": [],
            }

    monkeypatch.setattr(
        workspace,
        "_build_evidence_package_verifier",
        lambda: FakeVerifier(),
    )
    monkeypatch.setattr(
        "logviewer.pro.investigation.workspace.Prompt.ask",
        lambda *args, **kwargs: "",
    )

    workspace._verify_evidence_package(investigation)

    assert captured["path"].name == (
        "investigation_TEST-15G_evidence.zip"
    )


def test_verification_displays_failed_artifact(
    monkeypatch,
) -> None:
    workspace = _workspace()
    investigation = _investigation()

    class FakeVerifier:
        def verify(self, package_path):
            return {
                "status": "failed",
                "verified": False,
                "algorithm": "SHA-256",
                "investigation": {
                    "id": "TEST-15G",
                    "title": "Workspace Verification Test",
                },
                "files": [
                    {
                        "path": "investigation_TEST-15G/report.md",
                        "format": "md",
                        "expected_size": 100,
                        "actual_size": 110,
                        "expected_sha256": "a" * 64,
                        "actual_sha256": "b" * 64,
                        "verified": False,
                    }
                ],
                "errors": [
                    "Size mismatch for report.md."
                ],
                "warnings": [],
                "limitations": [
                    "Verification is not a legal chain-of-custody procedure."
                ],
            }

    monkeypatch.setattr(
        workspace,
        "_build_evidence_package_verifier",
        lambda: FakeVerifier(),
    )
    monkeypatch.setattr(
        "logviewer.pro.investigation.workspace.Prompt.ask",
        lambda *args, **kwargs: "",
    )

    workspace._verify_evidence_package(investigation)


def test_report_menu_contains_verification_option(
    monkeypatch,
) -> None:
    workspace = _workspace()
    investigation = _investigation()

    choices_seen = []

    def fake_prompt(*args, **kwargs):
        choices = kwargs.get("choices")
        if choices:
            choices_seen.append(list(choices))
        return "8"

    monkeypatch.setattr(
        "logviewer.pro.investigation.workspace.Prompt.ask",
        fake_prompt,
    )

    workspace._report_menu(investigation)

    assert choices_seen
    assert choices_seen[-1] == [
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
    ]
