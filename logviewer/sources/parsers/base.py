from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from ...events import Event


class LogParser(ABC):
    """
    Base interface for all LogViewer log parsers.

    Each parser is responsible for:
        1. Identifying whether it supports a source.
        2. Parsing supported log lines.
        3. Returning normalized Event objects.
    """

    name: str = "unknown"
    description: str = ""

    @abstractmethod
    def can_parse(self, path: Path) -> bool:
        """
        Return True when this parser can handle the given log source.
        """
        raise NotImplementedError

    @abstractmethod
    def parse_line(self, line: str, source: Path) -> Optional[Event]:
        """
        Parse one line from the source.

        Returns:
            Event if the line can be parsed.
            None if the line should be ignored.
        """
        raise NotImplementedError

    def parse_file(self, path: Path) -> List[Event]:
        """
        Parse an entire log file using this parser.
        """

        if not path.is_file():
            return []

        events = []

        try:
            with path.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:

                for line in handle:
                    event = self.parse_line(
                        line,
                        path,
                    )

                    if event is not None:
                        events.append(event)

        except (OSError, PermissionError):
            return []

        return events
