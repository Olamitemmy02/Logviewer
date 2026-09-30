"""
Real-event loader for Core Security Analysis.

Loads real events from LogViewer's existing ingestion pipeline and
provides source-level status information for the Security Analysis UI.

No demonstration, fabricated, or test events are created here.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from logviewer.events import Event
from logviewer.discovery import discover_sources
from logviewer.analysis.events.service import EventService


DEFAULT_JOURNAL_LIMIT = 5000

STATUS_ANALYZED = "ANALYZED"
STATUS_EMPTY = "EMPTY"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_PERMISSION_DENIED = "PERMISSION DENIED"
STATUS_READ_ERROR = "READ ERROR"
STATUS_UNSUPPORTED = "UNSUPPORTED"


SOURCE_KIND_FILESYSTEM = "FILESYSTEM"
SOURCE_KIND_JOURNAL = "JOURNAL"
SOURCE_KIND_SNORT = "SNORT"
SOURCE_KIND_BACKUP = "BACKUP"
SOURCE_KIND_ROTATED = "ROTATED"
SOURCE_KIND_COMPRESSED_ROTATION = "COMPRESSED ROTATION"


JOURNAL_ROOT = Path("/var/log/journal")
SNORT_ROOTS = (
    Path("/var/log/snort"),
    Path("/var/log/snort3"),
)

BACKUP_SUFFIXES = {
    ".backup",
    ".bak",
    ".old",
    ".orig",
    ".save",
}


@dataclass
class SourceStatus:
    """
    Describes the ingestion state of one logical security-event source.
    """

    name: str
    status: str
    events: int = 0
    paths: List[str] = field(default_factory=list)
    parser: Optional[str] = None
    description: Optional[str] = None
    error: Optional[str] = None
    source_kind: str = SOURCE_KIND_FILESYSTEM

    @property
    def analyzed(self) -> bool:
        return self.status == STATUS_ANALYZED


@dataclass
class SecurityAnalysisLoadResult:
    """
    Complete result returned by the Security Analysis ingestion layer.
    """

    events: List[Event] = field(default_factory=list)
    sources: List[SourceStatus] = field(default_factory=list)

    @property
    def total_events(self) -> int:
        return len(self.events)

    @property
    def analyzed_sources(self) -> int:
        return sum(
            source.status == STATUS_ANALYZED
            for source in self.sources
        )

    @property
    def empty_sources(self) -> int:
        return sum(
            source.status == STATUS_EMPTY
            for source in self.sources
        )

    @property
    def unavailable_sources(self) -> int:
        return sum(
            source.status == STATUS_UNAVAILABLE
            for source in self.sources
        )

    @property
    def permission_denied_sources(self) -> int:
        return sum(
            source.status == STATUS_PERMISSION_DENIED
            for source in self.sources
        )

    @property
    def read_error_sources(self) -> int:
        return sum(
            source.status == STATUS_READ_ERROR
            for source in self.sources
        )

    @property
    def unsupported_sources(self) -> int:
        return sum(
            source.status == STATUS_UNSUPPORTED
            for source in self.sources
        )


def load_security_events(
    journal_limit: int = DEFAULT_JOURNAL_LIMIT,
) -> List[Event]:
    """
    Backward-compatible event-only loader.
    """

    result = load_security_analysis(
        journal_limit=journal_limit,
    )

    return result.events


def load_security_analysis(
    journal_limit: int = DEFAULT_JOURNAL_LIMIT,
) -> SecurityAnalysisLoadResult:
    """
    Load real security events and source ingestion status.

    Sources:
        - discovered filesystem logs
        - Snort
        - systemd journal

    Journal-managed binary files and Snort-managed files are not
    ingested through the generic filesystem pipeline. They are handled
    by their dedicated readers.
    """

    service = EventService()
    result = SecurityAnalysisLoadResult()

    result.sources.extend(
        _load_filesystem_sources(
            service=service,
            result=result,
        )
    )

    result.sources.append(
        _load_snort_source(
            service=service,
            result=result,
        )
    )

    result.sources.append(
        _load_journal_source(
            service=service,
            result=result,
            limit=journal_limit,
        )
    )

    result.events = service.sort_events(
        result.events
    )

    return result


def _load_filesystem_sources(
    service: EventService,
    result: SecurityAnalysisLoadResult,
) -> List[SourceStatus]:
    """
    Load supported filesystem log sources.

    Rotated files are grouped under their logical source name.

    Journal-managed binary files and Snort-managed files are excluded
    here because they have dedicated ingestion paths.
    """

    discovered = discover_sources()

    logical_sources = {}

    for source in discovered:

        path = getattr(
            source,
            "path",
            None,
        )

        if path is None:
            continue

        path = Path(path)

        if _is_journal_managed_path(path):
            continue

        if _is_snort_managed_path(path):
            continue

        logical_name = _logical_source_name(
            path
        )

        entry = logical_sources.setdefault(
            logical_name,
            {
                "paths": [],
                "sources": [],
            },
        )

        entry["paths"].append(path)
        entry["sources"].append(source)

    statuses = []

    for name in sorted(
        logical_sources,
        key=str.casefold,
    ):

        data = logical_sources[name]

        statuses.append(
            _ingest_logical_filesystem_source(
                name=name,
                paths=data["paths"],
                source_infos=data["sources"],
                service=service,
                result=result,
            )
        )

    return statuses


def _ingest_logical_filesystem_source(
    name: str,
    paths: List[Path],
    source_infos: list,
    service: EventService,
    result: SecurityAnalysisLoadResult,
) -> SourceStatus:
    """
    Ingest all physical files belonging to one logical source.

    The source is represented as one logical entry while its physical
    files retain their individual paths for diagnostics.
    """

    source_status = SourceStatus(
        name=name,
        status=STATUS_UNAVAILABLE,
        paths=[
            str(path)
            for path in paths
        ],
        source_kind=SOURCE_KIND_FILESYSTEM,
    )

    supported_infos = []
    unsupported_infos = []

    for info in source_infos:

        status = getattr(
            info,
            "status",
            "UNSUPPORTED",
        )

        if status in {
            "SUPPORTED",
            "PARTIAL",
            "ROTATED",
        }:

            supported_infos.append(info)

        elif status in {
            "UNREADABLE",
            "PERMISSION DENIED",
        }:

            source_status.status = (
                STATUS_PERMISSION_DENIED
            )

        elif status == "UNSUPPORTED":

            unsupported_infos.append(info)

    source_status.source_kind = (
        _determine_logical_source_kind(
            paths
        )
    )

    if source_status.source_kind == SOURCE_KIND_BACKUP:
        source_status.description = (
            "Backup artifact discovered under /var/log. "
            "It is not treated as an active security-event source."
        )

    elif source_status.source_kind == SOURCE_KIND_COMPRESSED_ROTATION:
        source_status.description = (
            "Logical log source containing compressed rotated "
            "log files."
        )

    elif source_status.source_kind == SOURCE_KIND_ROTATED:
        source_status.description = (
            "Logical log source containing rotated log files."
        )

    if not supported_infos:

        if (
            source_status.status
            == STATUS_PERMISSION_DENIED
        ):

            source_status.error = (
                "One or more files could not be read."
            )

            return source_status

        if unsupported_infos:

            source_status.status = (
                STATUS_UNSUPPORTED
            )

            source_status.error = (
                "No supported parser is available "
                "for this source."
            )

            return source_status

        readable_existing = [
            info
            for info in source_infos
            if getattr(
                info,
                "readable",
                False,
            )
        ]

        if readable_existing:

            source_status.status = (
                STATUS_EMPTY
            )

            return source_status

        source_status.status = (
            STATUS_UNAVAILABLE
        )

        return source_status

    total_events = 0
    successful_paths = 0
    errors = []
    parsers = set()

    for info in supported_infos:

        path = Path(
            getattr(
                info,
                "path",
                "",
            )
        )

        try:

            events = service.from_file(
                path
            )

            if events:

                result.events.extend(
                    events
                )

                total_events += len(
                    events
                )

            successful_paths += 1

            parser_name = getattr(
                info,
                "parser",
                None,
            )

            if parser_name:

                parsers.add(
                    parser_name
                )

        except PermissionError:

            errors.append(
                f"{path}: permission denied"
            )

        except OSError as exc:

            errors.append(
                f"{path}: {exc}"
            )

        except Exception as exc:

            errors.append(
                f"{path}: {exc}"
            )

    source_status.events = total_events

    if parsers:

        source_status.parser = (
            ", ".join(
                sorted(parsers)
            )
        )

    if total_events > 0:

        source_status.status = (
            STATUS_ANALYZED
        )

    elif errors:

        if any(
            "permission denied"
            in error.lower()
            for error in errors
        ):

            source_status.status = (
                STATUS_PERMISSION_DENIED
            )

        else:

            source_status.status = (
                STATUS_READ_ERROR
            )

        source_status.error = (
            "; ".join(errors)
        )

    elif successful_paths > 0:

        source_status.status = (
            STATUS_EMPTY
        )

    else:

        source_status.status = (
            STATUS_EMPTY
        )

    return source_status


def _load_snort_source(
    service: EventService,
    result: SecurityAnalysisLoadResult,
) -> SourceStatus:
    """
    Load real Snort events using the status-aware Snort reader.
    """

    from logviewer.snort.reader import (
        read_snort_events_with_status,
    )

    source = SourceStatus(
        name="Snort",
        status=STATUS_UNAVAILABLE,
        source_kind=SOURCE_KIND_SNORT,
        description=(
            "Dedicated Snort ingestion source. Snort-managed "
            "files are excluded from generic filesystem analysis."
        ),
    )

    try:

        read_result = (
            read_snort_events_with_status()
        )

    except Exception as exc:

        source.status = STATUS_READ_ERROR
        source.error = str(exc)

        return source

    path = read_result.get(
        "path"
    )

    if path:

        source.paths = [
            str(path)
        ]

    source.status = read_result.get(
        "status",
        STATUS_READ_ERROR,
    )

    source.error = read_result.get(
        "error"
    )

    events = read_result.get(
        "events",
        [],
    )

    if events:

        result.events.extend(
            events
        )

        source.events = len(
            events
        )

    source.parser = "snort-csv"

    return source


def _load_journal_source(
    service: EventService,
    result: SecurityAnalysisLoadResult,
    limit: int,
) -> SourceStatus:
    """
    Load systemd journal using the status-aware journal reader.

    Journal binary files under /var/log/journal are intentionally not
    processed by the generic filesystem loader.
    """

    source = SourceStatus(
        name="systemd journal",
        status=STATUS_UNAVAILABLE,
        source_kind=SOURCE_KIND_JOURNAL,
        description=(
            "Dedicated systemd journal ingestion source. "
            "Binary journal files are handled by journalctl."
        ),
    )

    journal = service.journal

    try:

        read_result = (
            journal.read_with_status(
                limit=limit
            )
        )

    except AttributeError:

        source.status = STATUS_READ_ERROR
        source.error = (
            "JournalReader does not provide "
            "read_with_status()."
        )

        return source

    except PermissionError:

        source.status = (
            STATUS_PERMISSION_DENIED
        )

        source.error = (
            "Permission denied while reading "
            "the systemd journal."
        )

        return source

    except OSError as exc:

        source.status = (
            STATUS_READ_ERROR
        )

        source.error = str(exc)

        return source

    except Exception as exc:

        source.status = (
            STATUS_READ_ERROR
        )

        source.error = str(exc)

        return source

    source.status = read_result.status
    source.error = read_result.error
    source.parser = (
        "systemd-journal-json"
    )

    events = read_result.events

    if events:

        result.events.extend(
            events
        )

        source.events = len(
            events
        )

    return source


def _is_journal_managed_path(
    path: Path,
) -> bool:
    """
    Determine whether a path belongs to systemd's persistent journal.

    These files are binary journal storage and must not be treated as
    ordinary text log sources.
    """

    try:

        resolved = path.resolve()

    except OSError:

        resolved = path

    try:

        relative = resolved.relative_to(
            JOURNAL_ROOT
        )

        return bool(relative.parts)

    except ValueError:

        pass

    name = path.name.lower()

    return (
        name.endswith(".journal")
        or name.endswith(".journal~")
    )


def _is_snort_managed_path(
    path: Path,
) -> bool:
    """
    Determine whether a path belongs to a dedicated Snort source.
    """

    try:

        resolved = path.resolve()

    except OSError:

        resolved = path

    for root in SNORT_ROOTS:

        try:

            relative = resolved.relative_to(
                root
            )

            if relative.parts:
                return True

        except ValueError:

            continue

    return False


def _is_backup_path(
    path: Path,
) -> bool:
    """
    Determine whether a physical path appears to be a backup artifact.
    """

    name = path.name.lower()

    for suffix in BACKUP_SUFFIXES:

        if name.endswith(suffix):
            return True

    return False


def _is_compressed_path(
    path: Path,
) -> bool:
    """
    Determine whether a physical path is gzip-compressed.
    """

    return path.name.lower().endswith(
        ".gz"
    )


def _is_rotated_path(
    path: Path,
) -> bool:
    """
    Determine whether a physical path is a numbered rotation.

    Examples:
        auth.log.1
        auth.log.2.gz
        error.log.10
    """

    name = path.name.lower()

    if name.endswith(".gz"):
        name = name[:-3]

    parts = name.split(".")

    return (
        len(parts) >= 2
        and parts[-1].isdigit()
    )


def _determine_logical_source_kind(
    paths: List[Path],
) -> str:
    """
    Determine the most useful diagnostic kind for a logical source.

    Priority:
        backup
        compressed rotation
        rotated
        filesystem
    """

    if any(
        _is_backup_path(path)
        for path in paths
    ):

        return SOURCE_KIND_BACKUP

    if any(
        _is_rotated_path(path)
        and _is_compressed_path(path)
        for path in paths
    ):

        return SOURCE_KIND_COMPRESSED_ROTATION

    if any(
        _is_rotated_path(path)
        for path in paths
    ):

        return SOURCE_KIND_ROTATED

    return SOURCE_KIND_FILESYSTEM


def _logical_source_name(
    path: Path,
) -> str:
    """
    Convert a physical log path into a logical source name.

    Examples:

        /var/log/auth.log
            -> auth.log

        /var/log/auth.log.1
            -> auth.log

        /var/log/auth.log.2.gz
            -> auth.log

        /var/log/apache2/error.log
            -> apache2/error.log
    """

    try:

        relative = path.relative_to(
            "/var/log"
        )

    except ValueError:

        relative = path

    parts = list(
        relative.parts
    )

    if not parts:
        return path.name

    filename = parts[-1]

    if filename.lower().endswith(
        ".gz"
    ):

        filename = filename[:-3]

    filename_parts = filename.split(
        "."
    )

    if (
        len(filename_parts) >= 2
        and filename_parts[-1].isdigit()
    ):

        filename = ".".join(
            filename_parts[:-1]
        )

    parts[-1] = filename

    return "/".join(parts)


def _is_readable(
    path: Path,
) -> bool:
    """
    Test whether the current process can actually open a source.
    """

    try:

        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ):

            return True

    except (
        OSError,
        PermissionError,
    ):

        return False
