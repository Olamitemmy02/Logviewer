from __future__ import annotations

import hashlib
import json
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class InvestigationEvidencePackageBuilder:
    """
    Build an integrity-oriented ZIP package for a Pro investigation.

    The package contains the existing generated Markdown and JSON reports
    plus a manifest containing SHA-256 hashes for those report artifacts.

    This provides file-integrity metadata but does not by itself establish
    legal chain of custody or prove that the underlying evidence is genuine.
    """

    PACKAGE_VERSION = "1.0"
    DEFAULT_EXPORT_DIRECTORY = "exports"

    def __init__(
        self,
        export_directory: str | Path = DEFAULT_EXPORT_DIRECTORY,
        generator: Any | None = None,
    ) -> None:
        self.export_directory = Path(export_directory)

        if generator is None:
            from .investigation_report import InvestigationReportGenerator

            generator = InvestigationReportGenerator()

        self.generator = generator

    def build(
        self,
        investigation: Any,
    ) -> Path:
        """Build and return an evidence-package ZIP file."""

        investigation_id = self._investigation_id(investigation)
        safe_id = self._safe_investigation_id(investigation_id)

        self.export_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path = (
            self.export_directory
            / f"investigation_{safe_id}_evidence.zip"
        )

        with tempfile.TemporaryDirectory(
            prefix="logviewer_evidence_"
        ) as temporary_directory:
            staging_root = Path(temporary_directory)
            package_directory = (
                staging_root / f"investigation_{safe_id}"
            )
            package_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            markdown_path = package_directory / "report.md"
            json_path = package_directory / "report.json"

            self.generator.write_markdown(
                investigation,
                markdown_path,
            )
            self.generator.write_json(
                investigation,
                json_path,
            )

            manifest = self._build_manifest(
                investigation=investigation,
                package_directory=package_directory,
                safe_id=safe_id,
            )

            manifest_path = package_directory / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    manifest,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            self._write_zip(
                staging_root=staging_root,
                package_directory=package_directory,
                output_path=output_path,
            )

        return output_path

    def build_manifest(
        self,
        investigation: Any,
    ) -> Dict[str, Any]:
        """
        Build the manifest without creating a ZIP package.

        This is primarily useful for validation and testing.
        """

        investigation_id = self._investigation_id(investigation)
        safe_id = self._safe_investigation_id(investigation_id)

        with tempfile.TemporaryDirectory(
            prefix="logviewer_manifest_"
        ) as temporary_directory:
            package_directory = (
                Path(temporary_directory)
                / f"investigation_{safe_id}"
            )
            package_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            markdown_path = package_directory / "report.md"
            json_path = package_directory / "report.json"

            self.generator.write_markdown(
                investigation,
                markdown_path,
            )
            self.generator.write_json(
                investigation,
                json_path,
            )

            return self._build_manifest(
                investigation=investigation,
                package_directory=package_directory,
                safe_id=safe_id,
            )

    def _build_manifest(
        self,
        investigation: Any,
        package_directory: Path,
        safe_id: str,
    ) -> Dict[str, Any]:
        files = []

        for filename in ("report.md", "report.json"):
            path = package_directory / filename

            files.append(
                {
                    "path": (
                        f"investigation_{safe_id}/{filename}"
                    ),
                    "format": path.suffix.lstrip("."),
                    "size": path.stat().st_size,
                    "sha256": self._sha256(path),
                }
            )

        return {
            "package_version": self.PACKAGE_VERSION,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "investigation": {
                "investigation_id": self._investigation_id(
                    investigation
                ),
                "title": str(
                    getattr(
                        investigation,
                        "title",
                        "Untitled Investigation",
                    )
                ),
            },
            "files": files,
            "integrity": {
                "algorithm": "SHA-256",
                "scope": (
                    "Hashes cover the report.md and report.json "
                    "artifacts included in this package."
                ),
            },
            "limitations": [
                (
                    "The package provides file-integrity metadata "
                    "but does not independently establish legal "
                    "chain of custody."
                ),
                (
                    "The manifest does not prove the authenticity "
                    "or correctness of the underlying investigation data."
                ),
            ],
        }

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as handle:
            for chunk in iter(
                lambda: handle.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)

        return digest.hexdigest()

    @staticmethod
    def _investigation_id(investigation: Any) -> str:
        value = getattr(
            investigation,
            "investigation_id",
            None,
        )

        if value is None:
            raise ValueError(
                "Investigation does not contain an investigation_id."
            )

        value = str(value).strip()

        if not value:
            raise ValueError(
                "Investigation ID cannot be empty."
            )

        return value

    @staticmethod
    def _safe_investigation_id(investigation_id: str) -> str:
        safe_id = "".join(
            character
            if character.isalnum() or character in "-_."
            else "_"
            for character in str(investigation_id)
        ).strip("._")

        if not safe_id:
            return "investigation"

        return safe_id

    @staticmethod
    def _write_zip(
        staging_root: Path,
        package_directory: Path,
        output_path: Path,
    ) -> None:
        if output_path.exists():
            output_path.unlink()

        package_name = package_directory.name

        files: List[Path] = [
            package_directory / "report.md",
            package_directory / "report.json",
            package_directory / "manifest.json",
        ]

        with zipfile.ZipFile(
            output_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            for path in files:
                archive.write(
                    path,
                    arcname=f"{package_name}/{path.name}",
                )


__all__ = ["InvestigationEvidencePackageBuilder"]
