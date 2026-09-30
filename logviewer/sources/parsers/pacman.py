import re
from pathlib import Path
from typing import Optional

from .base import LogParser
from ...events import Event


# ----------------------------------------------------------------------
# Pacman log format
#
# Example:
#
# [2026-08-24T12:12:38+0100] [PACMAN] Running 'pacman -S package'
#
# Pacman may use timezone offsets with or without a colon:
#
# +0100
# +01:00
# ----------------------------------------------------------------------

PACMAN_PATTERN = re.compile(
    r"^\[(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}"
    r"T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"[+-]\d{2}:?\d{2}"
    r")\]\s+"
    r"\[PACMAN\]\s+"
    r"(?P<message>.*)$"
)


class PacmanParser(LogParser):
    """
    Parser for Arch Linux Pacman logs.

    Converts Pacman entries into normalized LogViewer Events.
    """

    name = "pacman"
    description = "Arch Linux Pacman package manager logs"

    def can_parse(self, path: Path) -> bool:
        """
        Determine whether this parser is appropriate for the source.
        """

        return path.name.lower() == "pacman.log"

    def parse_line(
        self,
        line: str,
        source: Path,
    ) -> Optional[Event]:
        """
        Parse one Pacman log line.
        """

        line = line.rstrip("\n")

        if not line.strip():
            return None

        match = PACMAN_PATTERN.match(line)

        if not match:
            return Event(
                timestamp="",
                source=str(source),
                severity="INFO",
                message=line,
                parse_status="unparsed",
                parser=self.name,
                raw={
                    "original_line": line,
                },
            )

        data = match.groupdict()

        message = data["message"]

        return Event(
            timestamp=data["timestamp"],
            source=str(source),
            severity="INFO",
            message=message,
            event_type=self._detect_event_type(message),
            parse_status="parsed",
            parser=self.name,
            action=self._detect_action(message),
            raw={
                "original_line": line,
                "source": "pacman",
            },
        )

    @staticmethod
    def _detect_event_type(message: str) -> str:
        """
        Determine the broad type of Pacman operation.
        """

        message_lower = message.lower()

        if "running 'pacman -s" in message_lower:
            return "package_install"

        if "running 'pacman -r" in message_lower:
            return "package_remove"

        if "running 'pacman -u" in message_lower:
            return "package_upgrade"

        if "running 'pacman -q" in message_lower:
            return "package_query"

        if "starting full system upgrade" in message_lower:
            return "system_upgrade"

        if "installed" in message_lower:
            return "package_install"

        if "removed" in message_lower:
            return "package_remove"

        if "upgraded" in message_lower:
            return "package_upgrade"

        return "pacman_event"

    @staticmethod
    def _detect_action(message: str) -> Optional[str]:
        """
        Determine the broad action represented by the Pacman entry.
        """

        message_lower = message.lower()

        if "pacman -s" in message_lower:
            return "install"

        if "pacman -r" in message_lower:
            return "remove"

        if "pacman -u" in message_lower:
            return "upgrade"

        if "pacman -q" in message_lower:
            return "query"

        if "installed" in message_lower:
            return "install"

        if "removed" in message_lower:
            return "remove"

        if "upgraded" in message_lower:
            return "upgrade"

        return None
