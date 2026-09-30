import re
from pathlib import Path
from typing import Optional

from ...events import Event
from .base import LogParser


class SyslogParser(LogParser):
    """
    Parser for traditional and ISO-style syslog records.

    Supported formats include:

        2026-09-08T12:53:41.318014+01:00 host process[123]: message

        2026-09-08T12:53:41.318014+01:00 host (process)[123]: message

        2026-09-08T12:53:41.318014+01:00 host (process): message

        2026-09-08T12:53:41.318014+01:00 host process]: message

        Jul 29 00:40:17 in-target: message

    The parser intentionally tolerates minor formatting variations found
    in real system logs while preserving the original source information.
    """

    name = "iso-syslog"

    description = (
        "ISO-8601 and traditional syslog records, including "
        "installer-style tagged records"
    )

    ISO_HEADER = re.compile(
        r"^(?P<timestamp>"
        r"\d{4}-\d{2}-\d{2}"
        r"T"
        r"\d{2}:\d{2}:\d{2}"
        r"(?:[.,]\d+)?"
        r"(?:Z|[+-]\d{2}:\d{2})?"
        r")"
        r"\s+"
        r"(?P<host>\S+)"
        r"\s+"
        r"(?P<tag>.+?)"
        r":"
        r"(?:\s(?P<message>.*))?$"
    )

    TRADITIONAL_HEADER = re.compile(
        r"^(?P<timestamp>"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"\s+"
        r"\d{1,2}"
        r"\s+"
        r"\d{2}:\d{2}:\d{2}"
        r")"
        r"\s+"
        r"(?P<host>\S+)"
        r"\s+"
        r"(?P<tag>.+?)"
        r":"
        r"(?:\s(?P<message>.*))?$"
    )

    INSTALLER_HEADER = re.compile(
        r"^(?P<timestamp>"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"\s+"
        r"\d{1,2}"
        r"\s+"
        r"\d{2}:\d{2}:\d{2}"
        r")"
        r"\s+"
        r"(?P<tag>[A-Za-z0-9_.@/-]+)"
        r":"
        r"(?:\s(?P<message>.*))?$"
    )

    def can_parse(self, path: Path) -> bool:
        """
        Return True for known syslog-style text log names.
        """
        name = path.name.lower()

        return (
            name in {
                "syslog",
                "auth.log",
                "user.log",
                "kern.log",
                "cron.log",
                "installer",
            }
            or name.startswith("syslog.")
            or name.startswith("auth.log.")
            or name.startswith("user.log.")
            or name.startswith("kern.log.")
            or name.startswith("cron.log.")
        )

    def parse_line(
        self,
        line: str,
        source: Path,
    ) -> Optional[Event]:
        """
        Parse one syslog line into a normalized Event.

        Leading NUL padding is removed because some real log records
        contain NUL bytes before an otherwise valid syslog record.
        """

        original_line = line.rstrip("\r\n")

        if not original_line.strip():
            return None

        normalized_line = original_line.lstrip("\x00")

        if not normalized_line.strip():
            return Event(
                timestamp="",
                source=str(source),
                severity="INFO",
                message="",
                parse_status="unparsed",
                parser=self.name,
                raw={
                    "original_line": original_line,
                    "parse_error": "nul-padding-only",
                },
            )

        nul_padding_detected = (
            normalized_line != original_line
        )

        # ---------------------------------------------------------
        # ISO-8601 syslog
        # ---------------------------------------------------------

        match = self.ISO_HEADER.fullmatch(normalized_line)

        if match:
            data = match.groupdict()

            return self._build_standard_event(
                data=data,
                source=source,
                original_line=original_line,
                nul_padding_detected=nul_padding_detected,
            )

        # ---------------------------------------------------------
        # Traditional syslog
        # ---------------------------------------------------------

        match = self.TRADITIONAL_HEADER.fullmatch(
            normalized_line
        )

        if match:
            data = match.groupdict()

            return self._build_standard_event(
                data=data,
                source=source,
                original_line=original_line,
                nul_padding_detected=nul_padding_detected,
            )

        # ---------------------------------------------------------
        # Debian installer-style syslog
        #
        # Example:
        #
        # Jul 29 00:40:17 in-target: ^M
        # Jul 29 00:18:12 debootstrap:
        # Jul 29 00:18:11 debootstrap: libpam-modules
        # ---------------------------------------------------------

        match = self.INSTALLER_HEADER.fullmatch(
            normalized_line
        )

        if match:
            data = match.groupdict()

            raw = {
                "original_line": original_line,
                "installer_style": True,
                "tag": data.get("tag"),
            }

            if nul_padding_detected:
                raw["nul_padding_detected"] = True

            return Event(
                timestamp=data["timestamp"],
                source=str(source),
                severity="INFO",
                message=(data.get("message") or "").strip(),
                event_type="installer",
                parse_status="parsed",
                parser=self.name,
                process=data.get("tag"),
                raw=raw,
            )

        # ---------------------------------------------------------
        # Unparsed record
        # ---------------------------------------------------------

        raw = {
            "original_line": original_line,
            "parse_error": "unrecognized-syslog-format",
        }

        if nul_padding_detected:
            raw["nul_padding_detected"] = True

        return Event(
            timestamp="",
            source=str(source),
            severity="INFO",
            message=normalized_line,
            event_type="syslog",
            parse_status="unparsed",
            parser=self.name,
            raw=raw,
        )

    def _build_standard_event(
        self,
        data: dict,
        source: Path,
        original_line: str,
        nul_padding_detected: bool,
    ) -> Event:
        """
        Build a normalized Event from a standard syslog record.

        The tag/process field is normalized separately so that slightly
        malformed or implementation-specific wrappers do not cause the
        entire record to become unparsed.
        """

        original_tag = (data.get("tag") or "").strip()

        process, pid = self._normalize_tag(original_tag)

        raw = {
            "original_line": original_line,
            "original_tag": original_tag,
        }

        if nul_padding_detected:
            raw["nul_padding_detected"] = True

        return Event(
            timestamp=data["timestamp"],
            source=str(source),
            severity="INFO",
            message=(data.get("message") or "").strip(),
            event_type="syslog",
            parse_status="parsed",
            parser=self.name,
            host=data.get("host"),
            process=process,
            pid=pid,
            raw=raw,
        )

    @staticmethod
    def _normalize_tag(tag: str):
        """
        Normalize common process/tag representations.

        Examples:

            gdm-password]
                -> ("gdm-password", None)

            (systemd)
                -> ("systemd", None)

            (haveged)[476]
                -> ("haveged", 476)

            (generato[28430]
                -> ("generato", 28430)

            systemd-logind[495]
                -> ("systemd-logind", 495)

            sshd
                -> ("sshd", None)
        """

        value = tag.strip()

        if not value:
            return None, None

        pid = None

        # First look for a PID enclosed in square brackets.
        pid_match = re.search(
            r"\[(\d+)\]?$",
            value,
        )

        if pid_match:
            pid = int(pid_match.group(1))

            value = value[:pid_match.start()]

        # Remove trailing unmatched or matched brackets.
        value = value.rstrip("]")

        # Remove surrounding parentheses.
        if value.startswith("("):
            value = value[1:]

        value = value.rstrip(")")

        # A few records can have a malformed opening parenthesis
        # immediately before a process name.
        value = value.lstrip("(")

        value = value.strip()

        return value or None, pid

    @staticmethod
    def _to_int(value):
        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None
