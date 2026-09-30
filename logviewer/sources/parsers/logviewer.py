import re
from pathlib import Path
from typing import Optional

from ...events import Event
from .base import LogParser


class LogViewerParser(LogParser):
    """
    Parser for LogViewer's own application log.

    The parser is directory-independent.

    Supported examples:

        /var/log/logviewer.log
        /opt/logviewer/logviewer.log
        /home/dave/logs/logviewer.log

    Rotated and compressed variants are also supported:

        logviewer.log.1
        logviewer.log.2
        logviewer.log.1.gz
        logviewer.log.2.gz

    Expected record format:

        2026-09-15 10:15:49,670 | INFO | [system] Application started

    The parser identifies the source by filename rather than by
    directory, allowing LogViewer's application log location to
    change through configuration/settings.
    """

    name = "logviewer"

    description = (
        "LogViewer application events and internal operational messages"
    )

    HEADER = re.compile(
        r"^(?P<timestamp>"
        r"\d{4}-\d{2}-\d{2}"
        r"\s+"
        r"\d{2}:\d{2}:\d{2}"
        r"(?:[.,]\d+)?"
        r")"
        r"\s*\|\s*"
        r"(?P<severity>[A-Za-z]+)"
        r"\s*\|\s*"
        r"\[(?P<category>[^\]]+)\]"
        r"\s*"
        r"(?P<message>.*)$"
    )

    def can_parse(self, path: Path) -> bool:
        """
        Determine whether a path contains a LogViewer application log.

        Directory location is deliberately ignored.

        Supported filenames:

            logviewer.log
            logviewer.log.1
            logviewer.log.2
            logviewer.log.1.gz
            logviewer.log.2.gz
        """

        name = path.name.lower()

        # Remove gzip suffix before checking rotation.
        if name.endswith(".gz"):
            name = name[:-3]

        if name == "logviewer.log":
            return True

        return bool(
            re.fullmatch(
                r"logviewer\.log\.\d+",
                name,
            )
        )

    def parse_line(
        self,
        line: str,
        source: Path,
    ) -> Optional[Event]:
        """
        Parse one LogViewer application-log record.

        The physical source path is preserved in Event.source.
        """

        original_line = line.rstrip("\r\n")

        if not original_line.strip():
            return None

        normalized_line = original_line.strip()

        match = self.HEADER.fullmatch(
            normalized_line
        )

        if not match:
            return Event(
                timestamp="",
                source=str(source),
                severity="INFO",
                message=normalized_line,
                event_type="application",
                parse_status="unparsed",
                parser=self.name,
                process="logviewer",
                raw={
                    "original_line": original_line,
                    "parse_error": (
                        "unrecognized-logviewer-format"
                    ),
                },
            )

        data = match.groupdict()

        severity = (
            data.get("severity") or "INFO"
        ).strip().upper()

        category = (
            data.get("category") or "unknown"
        ).strip()

        message = (
            data.get("message") or ""
        ).strip()

        return Event(
            timestamp=data["timestamp"],
            source=str(source),
            severity=severity,
            message=message,
            event_type="application",
            parse_status="parsed",
            parser=self.name,
            process="logviewer",
            raw={
                "original_line": original_line,
                "category": category,
            },
        )

