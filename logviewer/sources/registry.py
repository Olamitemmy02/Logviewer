from pathlib import Path
from typing import List, Optional

from .parsers.base import LogParser
from .parsers.syslog import SyslogParser
from .parsers.pacman import PacmanParser
from .parsers.maltrail import MaltrailParser
from .parsers.apache import ApacheParser
from .parsers.ufw import UfwParser
from .parsers.postgresql import PostgreSQLParser
from .parsers.logviewer import LogViewerParser
from .parsers.crowdsec import CrowdSecParser
from .apt.parser import AptParser


class ParserRegistry:
    """
    Central registry for LogViewer log parsers.

    The registry is responsible only for parser selection.
    Individual parsers determine whether they can handle a
    particular source.
    """

    def __init__(self):
        self._parsers: List[LogParser] = []

        # Specialized parsers
        self.register(AptParser())
        self.register(UfwParser())
        self.register(PostgreSQLParser())
        self.register(LogViewerParser())
        self.register(CrowdSecParser())

        # General and existing parsers
        self.register(SyslogParser())
        self.register(PacmanParser())
        self.register(MaltrailParser())
        self.register(ApacheParser())

    def register(
        self,
        parser: LogParser,
    ) -> None:
        """
        Register a parser if another parser with the same
        name has not already been registered.
        """

        if any(
            existing.name == parser.name
            for existing in self._parsers
        ):
            return

        self._parsers.append(parser)

    def get_parser(
        self,
        path,
    ) -> Optional[LogParser]:
        """
        Return the first parser capable of handling the source.
        """

        path = Path(path)

        for parser in self._parsers:
            try:
                if parser.can_parse(path):
                    return parser
            except (
                OSError,
                PermissionError,
            ):
                continue

        return None

    def parse_file(
        self,
        path,
    ):
        """
        Resolve a parser and parse the supplied file.
        """

        path = Path(path)

        parser = self.get_parser(path)

        if parser is None:
            return None, []

        return parser, parser.parse_file(path)

    def parsers(self) -> List[LogParser]:
        """
        Return all registered parser instances.
        """

        return list(self._parsers)

    def parser_info(self) -> List[dict]:
        """
        Return metadata for all registered parsers.
        """

        return [
            {
                "name": parser.name,
                "description": parser.description,
            }
            for parser in self._parsers
        ]
