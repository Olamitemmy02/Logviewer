from __future__ import annotations

import gzip
import re
from pathlib import Path
from typing import Dict, List, Optional, TextIO, Tuple

from logviewer.events import Event


class AptParser:
    """
    Parser for Debian/Kali APT logs.

    Supported sources:
        - /var/log/apt/history.log
        - /var/log/apt/term.log
        - Rotated APT logs such as:
            history.log.1
            history.log.2.gz
            term.log.1
            term.log.2.gz

    APT history transactions are converted into normalized Events.
    Terminal output is converted into individual package-operation events.

    Raw source information is preserved for investigation and reporting.

    Coverage is measured using logical APT records rather than raw
    physical lines.
    """

    name = "apt"
    description = "APT package-management history and terminal logs"

    HISTORY_FIELDS = {
        "start-date": "start_date",
        "end-date": "end_date",
        "commandline": "commandline",
        "requested-by": "requested_by",
        "install": "install",
        "remove": "remove",
        "purge": "purge",
        "upgrade": "upgrade",
        "downgrade": "downgrade",
        "error": "error",
    }

    TERM_PACKAGE_RE = re.compile(
        r"^(?P<action>"
        r"Selecting previously unselected package|"
        r"Preparing to unpack|"
        r"Unpacking|"
        r"Setting up|"
        r"Removing|"
        r"Purging"
        r")\s+(?P<package>.+?)(?:\.{3}|\.|$)"
    )

    PACKAGE_NAME_RE = re.compile(
        r"^(?P<name>[A-Za-z0-9][A-Za-z0-9+_.-]*)"
        r"(?::(?P<arch>[A-Za-z0-9_-]+))?"
        r"(?:\s+\([^)]*\))?$"
    )

    def can_parse(self, path: Path) -> bool:
        """
        Determine whether the path belongs to a supported APT log.

        Rotated and compressed names are normalized before checking.

        Examples:
            history.log
            history.log.1
            history.log.2.gz
            term.log
            term.log.1.gz
        """

        logical_name = self._logical_name(Path(path))

        return logical_name in {
            "history.log",
            "term.log",
        }

    def parse_file(self, path: Path) -> List[Event]:
        """
        Parse an APT log file.

        Both normal and gzip-compressed files are supported.
        The physical source path is preserved in the generated events.
        """

        path = Path(path)

        if not path.is_file():
            return []

        logical_name = self._logical_name(path)

        if logical_name not in {
            "history.log",
            "term.log",
        }:
            return []

        try:
            with self._open_text(path) as handle:
                lines = list(handle)
        except (
            OSError,
            PermissionError,
            EOFError,
            gzip.BadGzipFile,
        ):
            return []

        if logical_name == "history.log":
            return self.parse_history(lines, path)

        if logical_name == "term.log":
            return self.parse_term(lines, path)

        return []

    def measure_coverage(
        self,
        path: Path,
    ) -> Tuple[int, int, int, int]:
        """
        Measure coverage using APT's logical records rather than
        individual physical lines.

        Returns:

            total_units,
            parsed_units,
            unparsed_units,
            parser_errors

        history.log:
            One transaction is one logical unit.

        term.log:
            One recognized package operation is one logical unit.

            Informational terminal lines such as:
                Reading database...
                Processing triggers...
            are not treated as failed package records.
        """

        path = Path(path)

        if not path.is_file():
            return 0, 0, 0, 0

        logical_name = self._logical_name(path)

        if logical_name not in {
            "history.log",
            "term.log",
        }:
            return 0, 0, 0, 0

        try:
            with self._open_text(path) as handle:
                lines = list(handle)
        except (
            OSError,
            PermissionError,
            EOFError,
            gzip.BadGzipFile,
        ):
            return 0, 0, 0, 0

        if logical_name == "history.log":
            return self._measure_history_coverage(
                lines,
                path,
            )

        if logical_name == "term.log":
            return self._measure_term_coverage(lines)

        return 0, 0, 0, 0

    @staticmethod
    def _logical_name(path: Path) -> str:
        """
        Convert a physical APT log filename into its logical filename.

        Examples:

            history.log       -> history.log
            history.log.1     -> history.log
            history.log.2.gz  -> history.log
            term.log.1.gz     -> term.log
        """

        name = path.name

        if name.lower().endswith(".gz"):
            name = name[:-3]

        match = re.match(
            r"^(?P<base>.+)\.(?P<rotation>\d+)$",
            name,
        )

        if match:
            name = match.group("base")

        return name.lower()

    @staticmethod
    def _open_text(path: Path) -> TextIO:
        """
        Open a normal or gzip-compressed text file.

        APT rotated logs commonly use gzip compression.
        """

        if path.name.lower().endswith(".gz"):
            return gzip.open(
                path,
                "rt",
                encoding="utf-8",
                errors="replace",
            )

        return path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        )

    def _measure_history_coverage(
        self,
        lines: List[str],
        source: Path,
    ) -> Tuple[int, int, int, int]:
        """
        Measure history.log by transaction blocks.
        """

        total_units = 0
        parsed_units = 0
        unparsed_units = 0
        parser_errors = 0

        transaction: Dict[str, str] = {}

        def flush_transaction() -> None:
            nonlocal total_units, parsed_units, unparsed_units
            nonlocal parser_errors, transaction

            if not transaction:
                return

            total_units += 1

            try:
                event = self._build_history_event(
                    transaction,
                    [],
                    source,
                )
            except Exception:
                parser_errors += 1
                unparsed_units += 1
            else:
                if event is None:
                    unparsed_units += 1
                else:
                    parsed_units += 1

            transaction = {}

        for raw_line in lines:
            line = raw_line.rstrip("\r\n")

            if not line.strip():
                flush_transaction()
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            field_name = self.HISTORY_FIELDS.get(
                key.strip().lower()
            )

            if field_name:
                transaction[field_name] = value.strip()

        flush_transaction()

        return (
            total_units,
            parsed_units,
            unparsed_units,
            parser_errors,
        )

    def _measure_term_coverage(
        self,
        lines: List[str],
    ) -> Tuple[int, int, int, int]:
        """
        Measure term.log by recognized package-operation records.

        Non-package terminal messages are intentionally not counted
        as parser failures because they are contextual terminal output,
        not normalized package-operation records.
        """

        total_units = 0
        parsed_units = 0
        unparsed_units = 0
        parser_errors = 0

        for raw_line in lines:
            line = raw_line.rstrip("\r\n")

            if not line.strip():
                continue

            match = self.TERM_PACKAGE_RE.match(line)

            if not match:
                continue

            total_units += 1

            try:
                package = match.group("package").strip()

                if not package:
                    unparsed_units += 1
                    continue

                action = self._normalize_term_action(
                    match.group("action")
                )

                if not action:
                    unparsed_units += 1
                    continue

                parsed_units += 1

            except Exception:
                parser_errors += 1
                unparsed_units += 1

        return (
            total_units,
            parsed_units,
            unparsed_units,
            parser_errors,
        )

    def parse_history(
        self,
        lines: List[str],
        source: Path,
    ) -> List[Event]:
        events: List[Event] = []

        transaction: Dict[str, str] = {}
        raw_lines: List[str] = []

        def flush_transaction() -> None:
            nonlocal transaction, raw_lines

            if not transaction:
                raw_lines = []
                return

            event = self._build_history_event(
                transaction,
                raw_lines,
                source,
            )

            if event is not None:
                events.append(event)

            transaction = {}
            raw_lines = []

        for raw_line in lines:
            line = raw_line.rstrip("\r\n")

            if not line.strip():
                flush_transaction()
                continue

            raw_lines.append(line)

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            field_name = self.HISTORY_FIELDS.get(
                key.strip().lower()
            )

            if field_name:
                transaction[field_name] = value.strip()

        flush_transaction()

        return events

    def parse_term(
        self,
        lines: List[str],
        source: Path,
    ) -> List[Event]:
        events: List[Event] = []

        current_start: Optional[str] = None
        current_end: Optional[str] = None

        for raw_line in lines:
            line = raw_line.rstrip("\r\n")

            if not line.strip():
                continue

            if line.startswith("Log started:"):
                current_start = line.split(
                    ":",
                    1,
                )[1].strip()
                continue

            if line.startswith("Log ended:"):
                current_end = line.split(
                    ":",
                    1,
                )[1].strip()
                continue

            match = self.TERM_PACKAGE_RE.match(line)

            if not match:
                continue

            action_text = match.group("action")
            package = match.group("package").strip()

            action = self._normalize_term_action(
                action_text
            )

            events.append(
                Event(
                    timestamp=current_start or "",
                    source=str(source),
                    severity="INFO",
                    message=line,
                    event_type="apt_package_operation",
                    parse_status="parsed",
                    parser=self.name,
                    action=action,
                    raw={
                        "original_line": line,
                        "apt_action": action,
                        "package": package,
                        "log_started": current_start,
                        "log_ended": current_end,
                        "source_path": str(source),
                    },
                )
            )

        return events

    def _build_history_event(
        self,
        transaction: Dict[str, str],
        raw_lines: List[str],
        source: Path,
    ) -> Optional[Event]:
        start_date = transaction.get("start_date")

        if not start_date:
            return None

        commandline = transaction.get(
            "commandline",
            "",
        )

        requested_by = transaction.get(
            "requested_by"
        )

        operations: Dict[str, List[str]] = {}

        for field in (
            "install",
            "remove",
            "purge",
            "upgrade",
            "downgrade",
        ):
            value = transaction.get(field)

            if value:
                operations[field] = self._parse_packages(
                    value
                )

        if transaction.get("error"):
            severity = "ERROR"
            event_type = "apt_transaction_error"
        else:
            severity = "INFO"
            event_type = "apt_transaction"

        action = self._primary_action(operations)

        message_parts = []

        if commandline:
            message_parts.append(
                f"Command: {commandline}"
            )

        if requested_by:
            message_parts.append(
                f"Requested by: {requested_by}"
            )

        if action:
            message_parts.append(
                f"Action: {action}"
            )

        for operation, packages in operations.items():
            if packages:
                message_parts.append(
                    f"{operation.title()}: "
                    f"{', '.join(packages)}"
                )

        if transaction.get("error"):
            message_parts.append(
                f"Error: {transaction['error']}"
            )

        return Event(
            timestamp=start_date,
            source=str(source),
            severity=severity,
            message=" | ".join(message_parts),
            event_type=event_type,
            parse_status="parsed",
            parser=self.name,
            user=self._extract_user(requested_by),
            action=action,
            raw={
                "original_lines": list(raw_lines),
                "start_date": start_date,
                "end_date": transaction.get("end_date"),
                "commandline": commandline,
                "requested_by": requested_by,
                "operations": operations,
                "error": transaction.get("error"),
                "source_path": str(source),
            },
        )

    @classmethod
    def _parse_packages(
        cls,
        value: str,
    ) -> List[str]:
        """
        Split an APT package list on commas that are outside
        parentheses.

        Example:

            docker-cli:amd64 (28.5.2+dfsg4-4),
            docker-buildx:amd64 (0.29.1+ds1-4, automatic)

        becomes:

            [
                "docker-cli",
                "docker-buildx",
            ]
        """

        entries = []
        current = []
        depth = 0

        for character in value:
            if character == "(":
                depth += 1
                current.append(character)
                continue

            if character == ")":
                if depth > 0:
                    depth -= 1
                current.append(character)
                continue

            if character == "," and depth == 0:
                entry = "".join(current).strip()

                if entry:
                    entries.append(entry)

                current = []
                continue

            current.append(character)

        final_entry = "".join(current).strip()

        if final_entry:
            entries.append(final_entry)

        packages = []

        for entry in entries:
            match = cls.PACKAGE_NAME_RE.match(
                entry
            )

            if match:
                package = match.group("name")
            else:
                package = cls._fallback_package_name(
                    entry
                )

            if package:
                packages.append(package)

        return packages

    @staticmethod
    def _fallback_package_name(
        entry: str,
    ) -> str:
        """
        Conservative fallback for unusual APT package syntax.
        """

        value = entry.strip()

        if not value:
            return ""

        value = value.split(
            " ",
            1,
        )[0]

        value = value.split(
            ":",
            1,
        )[0]

        return value.strip(
            "(),"
        )

    @staticmethod
    def _extract_user(
        requested_by: Optional[str],
    ) -> Optional[str]:
        if not requested_by:
            return None

        match = re.match(
            r"^(?P<user>.+?)\s*\((?P<uid>\d+)\)$",
            requested_by,
        )

        if match:
            return match.group(
                "user"
            ).strip()

        return requested_by.strip() or None

    @staticmethod
    def _primary_action(
        operations: Dict[str, List[str]],
    ) -> Optional[str]:
        priority = (
            "install",
            "remove",
            "purge",
            "upgrade",
            "downgrade",
        )

        for action in priority:
            if operations.get(action):
                return action

        return None

    @staticmethod
    def _normalize_term_action(
        action: str,
    ) -> str:
        mapping = {
            "Selecting previously unselected package":
                "select",
            "Preparing to unpack":
                "prepare_unpack",
            "Unpacking":
                "unpack",
            "Setting up":
                "setup",
            "Removing":
                "remove",
            "Purging":
                "purge",
        }

        return mapping.get(
            action,
            action.lower().replace(
                " ",
                "_",
            ),
        )
