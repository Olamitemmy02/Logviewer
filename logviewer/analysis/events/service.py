from pathlib import Path
from typing import Iterable, List

from logviewer.events import Event
from logviewer.analysis.ingestion.engine import EventIngestionEngine
from logviewer.sources.journal.reader import JournalReader
from logviewer.analysis.normalization import parse_event_timestamp


class EventService:
    """
    High-level service for retrieving and working with normalized events.

    EventService coordinates ingestion and journal access while keeping
    event ordering consistent across different timestamp formats.
    """

    def __init__(self):
        self.ingestion = EventIngestionEngine()
        self.journal = JournalReader()

    def from_file(
        self,
        path,
    ) -> List[Event]:
        """
        Ingest events from a single log file.
        """

        return self.ingestion.ingest_file(
            path
        )

    def from_files(
        self,
        paths: Iterable,
    ) -> List[Event]:
        """
        Ingest events from multiple log files and return them chronologically.
        """

        events = self.ingestion.ingest_files(
            paths
        )

        return self.sort_events(
            events
        )

    def snort_events(
        self,
    ) -> List[Event]:
        """
        Retrieve normalized Snort events.
        """

        return self.ingestion.ingest_snort()

    def journal_events(
        self,
        limit: int = 1000,
    ) -> List[Event]:
        """
        Retrieve recent systemd journal events.
        """

        return self.journal.read(
            limit=limit
        )

    def journal_events_since(
        self,
        since: str,
        limit: int = 1000,
    ) -> List[Event]:
        """
        Retrieve systemd journal events since a specified time.
        """

        return self.journal.read_since(
            since=since,
            limit=limit,
        )

    def system_events(
        self,
        paths: Iterable,
    ) -> List[Event]:
        """
        Ingest events from system log files.
        """

        events = []

        for path in paths:
            path = Path(path)

            if not path.is_file():
                continue

            events.extend(
                self.ingestion.ingest_system_log(
                    path
                )
            )

        return self.sort_events(
            events
        )

    @staticmethod
    def filter_by_source(
        events,
        source,
    ):
        """
        Return events belonging to a specific source.
        """

        return [
            event
            for event in events
            if event.source == source
        ]

    @staticmethod
    def filter_by_severity(
        events,
        severity,
    ):
        """
        Return events matching a normalized severity.
        """

        severity = severity.upper()

        return [
            event
            for event in events
            if (
                event.severity or "INFO"
            ).upper() == severity
        ]

    @staticmethod
    def sort_events(
        events,
    ) -> List[Event]:
        """
        Sort events chronologically using the shared timestamp parser.

        Parseable timestamps are compared as timezone-aware UTC
        datetimes.

        Events with unparseable or missing timestamps are retained and
        placed after events with valid timestamps.

        The original Event objects are not modified.
        """

        def sort_key(
            event: Event,
        ):
            parsed = parse_event_timestamp(
                event.timestamp
            )

            if parsed is None:
                return (
                    1,
                    datetime_min_value(),
                    event.timestamp or "",
                )

            return (
                0,
                parsed,
                event.timestamp or "",
            )

        return sorted(
            events,
            key=sort_key,
        )


def datetime_min_value():
    """
    Return the minimum UTC datetime used for deterministic sorting
    of events without parseable timestamps.

    Kept as a small helper so EventService does not need to expose
    datetime implementation details elsewhere.
    """

    from datetime import datetime, timezone

    return datetime.min.replace(
        tzinfo=timezone.utc
    )
