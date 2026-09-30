from pathlib import Path
from typing import Iterable, List
import gzip

from logviewer.events import Event
from logviewer.snort.reader import read_snort_events
from logviewer.sources.registry import ParserRegistry
from logviewer.sources.parsers.base import LogParser


class EventIngestionEngine:
    """
    Central event ingestion layer for LogViewer.

    Responsibilities:

        - Select the appropriate parser.
        - Support structured and line-based parsers.
        - Read normal and gzip-compressed logs.
        - Resolve rotated logs to their logical parser source.
        - Preserve the real source path on generated events.
        - Keep Snort ingestion explicitly supported.
        - Return normalized Event objects to Core and Pro.

    Parser strategies:

        Structured parser:
            Explicitly overrides LogParser.parse_file()

        Line parser:
            Uses LogParser.parse_file() by default and therefore
            must be processed through parse_line() here.

    This distinction is important because LogParser provides a
    generic parse_file() implementation for line-oriented parsers.
    """

    def __init__(self):
        self.registry = ParserRegistry()

    def ingest_system_log(self, path) -> List[Event]:
        """
        Compatibility wrapper for existing callers.
        """
        return self.ingest_file(path)

    def ingest_snort(self) -> List[Event]:
        """
        Ingest live Snort events.
        """
        return read_snort_events()

    def ingest_file(self, path) -> List[Event]:
        """
        Ingest one real log source.

        Supports:

            - normal log files
            - structured file parsers
            - line-based parsers
            - rotated logs
            - gzip-compressed rotated logs
            - registered parser formats
            - live Snort CSV

        Returned events retain the actual physical source path.
        """

        path = Path(path)

        if not path.is_file():
            return []

        if self._is_snort_file(path):
            events = self.ingest_snort()

            return self._preserve_source(
                events,
                path,
            )

        parser_path = self._logical_parser_path(path)

        parser = self.registry.get_parser(
            parser_path
        )

        if parser is None:
            return []

        events = self._parse_file(
            path=path,
            parser=parser,
            parser_source=parser_path,
        )

        return self._preserve_source(
            events,
            path,
        )

    def ingest_files(
        self,
        paths: Iterable,
    ) -> List[Event]:
        """
        Ingest multiple sources through the same pipeline.
        """

        events = []

        for path in paths:
            events.extend(
                self.ingest_file(path)
            )

        return events

    def get_parser(self, path):
        """
        Return the parser selected for a source.

        Rotated files are resolved to their logical source before
        parser selection.
        """

        path = Path(path)

        parser_path = self._logical_parser_path(
            path
        )

        return self.registry.get_parser(
            parser_path
        )

    def get_parser_info(self) -> List[dict]:
        """
        Return information about all registered parsers.
        """

        return self.registry.parser_info()

    @staticmethod
    def _is_snort_file(path: Path) -> bool:
        """
        Identify LogViewer's live Snort CSV source.

        Backup files and rotated Snort files are deliberately
        excluded from the dedicated live reader.
        """

        normalized = str(path).lower()

        return (
            "snort" in normalized
            and path.name.lower() == "alert_csv.txt"
        )

    @staticmethod
    def _logical_parser_path(path: Path) -> Path:
        """
        Resolve rotated filenames to the logical filename expected
        by the parser registry.

        Examples:

            error.log
                -> error.log

            error.log.1
                -> error.log

            error.log.2.gz
                -> error.log

            access.log.5.gz
                -> access.log
        """

        name = path.name

        if name.lower().endswith(".gz"):
            name = name[:-3]

        parts = name.split(".")

        if (
            len(parts) >= 2
            and parts[-1].isdigit()
        ):
            name = ".".join(
                parts[:-1]
            )

        return path.with_name(name)

    @staticmethod
    def _open_text(path: Path):
        """
        Open plain-text and gzip-compressed files using the same
        interface.
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

    @staticmethod
    def _uses_structured_parser(parser) -> bool:
        """
        Determine whether a parser provides its own native
        file-level parsing implementation.

        LogParser itself provides a generic parse_file() method.
        That method does NOT make a parser structured.

        A parser is considered structured only when its concrete
        class overrides the base implementation.
        """

        parser_parse_file = getattr(
            type(parser),
            "parse_file",
            None,
        )

        return (
            parser_parse_file is not None
            and parser_parse_file is not LogParser.parse_file
        )

    def _parse_file(
        self,
        path: Path,
        parser,
        parser_source: Path,
    ) -> List[Event]:
        """
        Parse a source using the parser's preferred strategy.

        Native structured parsers receive the physical source path.

        Line-based parsers are read by the ingestion engine so that
        normal and gzip-compressed sources use the same code path.
        """

        if self._uses_structured_parser(parser):
            return self._parse_structured_file(
                path=path,
                parser=parser,
            )

        return self._parse_line_based_file(
            path=path,
            parser=parser,
            parser_source=parser_source,
        )

    @staticmethod
    def _parse_structured_file(
        path: Path,
        parser,
    ) -> List[Event]:
        """
        Use a parser's native file-level parsing method.

        Structured parsers are responsible for opening and
        interpreting the source according to their logical
        record structure.
        """

        try:
            events = parser.parse_file(
                path
            )
        except (
            OSError,
            PermissionError,
            EOFError,
        ):
            return []
        except Exception:
            return []

        if events is None:
            return []

        return list(events)

    def _parse_line_based_file(
        self,
        path: Path,
        parser,
        parser_source: Path,
    ) -> List[Event]:
        """
        Parse a line-oriented source using parse_line().

        The ingestion layer handles gzip files here so parsers do
        not need separate compressed-file implementations.
        """

        events = []

        try:
            with self._open_text(path) as handle:

                for line in handle:
                    if not line.strip():
                        continue

                    try:
                        event = parser.parse_line(
                            line,
                            parser_source,
                        )
                    except Exception:
                        event = None

                    if event is not None:
                        events.append(event)

        except (
            OSError,
            PermissionError,
            EOFError,
        ):
            return []

        return events

    @staticmethod
    def _preserve_source(
        events: Iterable[Event],
        source: Path,
    ) -> List[Event]:
        """
        Preserve the physical source path on every event.

        Parsers may need the logical filename to identify a format,
        but the resulting Event must identify the real file that
        produced it.
        """

        source_text = str(source)

        for event in events:
            event.source = source_text

            if not event.raw:
                event.raw = {}

            event.raw.setdefault(
                "source_path",
                source_text,
            )

        return list(events)

    @staticmethod
    def sort_events(
        events: Iterable[Event],
    ) -> List[Event]:
        """
        Sort normalized events chronologically.

        Events without timestamps are placed last.
        """

        return sorted(
            events,
            key=lambda event: (
                not bool(
                    (event.timestamp or "").strip()
                ),
                event.timestamp or "",
            ),
        )
