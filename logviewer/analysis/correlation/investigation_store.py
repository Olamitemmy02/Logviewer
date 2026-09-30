import json
from pathlib import Path
from typing import List, Optional

from .engine import CorrelationFinding
from .investigation import InvestigationContext


class InvestigationStore:
    """
    Persistent storage for LogViewer investigations.

    Investigations are stored as JSON case files.

    The underlying log dataset is not copied into the investigation.
    Only analyst-selected findings and notes are persisted.
    """

    FORMAT_NAME = "logviewer-investigation"
    FORMAT_VERSION = 1

    def __init__(
        self,
        directory: Optional[str] = None,
    ):
        if directory:
            self.directory = Path(
                directory
            ).expanduser()
        else:
            self.directory = (
                Path.home()
                / ".local"
                / "share"
                / "logviewer"
                / "investigations"
            )

        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def list_investigations(self) -> List[str]:
        """
        Return the names of saved investigations.
        """

        names = []

        for path in self.directory.glob("*.json"):
            if path.is_file():
                names.append(path.stem)

        return sorted(names)

    def save(
        self,
        investigation: InvestigationContext,
    ) -> Path:
        """
        Save an investigation atomically.
        """

        filename = self._safe_filename(
            investigation.name
        )

        path = self.directory / (
            f"{filename}.json"
        )

        payload = self._serialize(
            investigation
        )

        temporary = path.with_suffix(
            ".tmp"
        )

        temporary.write_text(
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        temporary.replace(path)

        return path

    def load(
        self,
        name: str,
    ) -> InvestigationContext:
        """
        Load a saved investigation.
        """

        path = self._resolve_path(name)

        if not path.exists():
            raise FileNotFoundError(
                f"Investigation not found: {name}"
            )

        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        self._validate_payload(
            payload
        )

        return self._deserialize(
            payload
        )

    def delete(
        self,
        name: str,
    ) -> bool:
        """
        Delete a saved investigation.
        """

        path = self._resolve_path(name)

        if not path.exists():
            return False

        path.unlink()

        return True

    def exists(
        self,
        name: str,
    ) -> bool:
        """
        Determine whether an investigation exists.
        """

        return self._resolve_path(
            name
        ).exists()

    def path_for(
        self,
        name: str,
    ) -> Path:
        """
        Return the filesystem path for an investigation.
        """

        return self._resolve_path(name)

    def _resolve_path(
        self,
        name: str,
    ) -> Path:
        filename = self._safe_filename(
            name
        )

        return self.directory / (
            f"{filename}.json"
        )

    @staticmethod
    def _safe_filename(
        name: str,
    ) -> str:
        """
        Convert an investigation name into
        a filesystem-safe filename.
        """

        value = str(name).strip()

        if not value:
            value = "untitled-investigation"

        allowed = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "-_."
        )

        value = "".join(
            character
            if character in allowed
            else "_"
            for character in value
        )

        value = value.strip("._")

        return (
            value
            or "untitled-investigation"
        )

    @classmethod
    def _serialize(
        cls,
        investigation: InvestigationContext,
    ) -> dict:
        return {
            "format": cls.FORMAT_NAME,
            "version": cls.FORMAT_VERSION,
            "name": investigation.name,
            "notes": list(
                investigation.notes
            ),
            "findings": [
                finding.as_dict()
                for finding in investigation.findings
            ],
        }

    @classmethod
    def _deserialize(
        cls,
        payload: dict,
    ) -> InvestigationContext:

        investigation = InvestigationContext(
            name=str(
                payload.get(
                    "name",
                    "Untitled Investigation",
                )
            )
        )

        investigation.notes = [
            str(note)
            for note in (
                payload.get(
                    "notes",
                    []
                )
                or []
            )
        ]

        for finding_data in (
            payload.get(
                "findings",
                []
            )
            or []
        ):
            if not isinstance(
                finding_data,
                dict,
            ):
                continue

            finding = (
                CorrelationFinding.from_dict(
                    finding_data
                )
            )

            investigation.add_finding(
                finding
            )

        return investigation

    @classmethod
    def _validate_payload(
        cls,
        payload: dict,
    ) -> None:

        if not isinstance(
            payload,
            dict,
        ):
            raise ValueError(
                "Invalid investigation file: "
                "root object must be a dictionary."
            )

        file_format = payload.get(
            "format"
        )

        if file_format != cls.FORMAT_NAME:
            raise ValueError(
                "Invalid investigation file format."
            )

        version = payload.get(
            "version"
        )

        if version != cls.FORMAT_VERSION:
            raise ValueError(
                f"Unsupported investigation "
                f"format version: {version}"
            )

        findings = payload.get(
            "findings",
            [],
        )

        if not isinstance(
            findings,
            list,
        ):
            raise ValueError(
                "Invalid investigation file: "
                "'findings' must be a list."
            )

        notes = payload.get(
            "notes",
            [],
        )

        if not isinstance(
            notes,
            list,
        ):
            raise ValueError(
                "Invalid investigation file: "
                "'notes' must be a list."
            )
