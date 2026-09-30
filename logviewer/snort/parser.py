import csv
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..events import Event


FIELDS = [
    "timestamp",
    "gid",
    "sid",
    "rev",
    "priority",
    "msg",
    "proto",
    "src_ap",
    "dst_ap",
    "rule",
    "action",
]


STATUS_ANALYZED = "ANALYZED"
STATUS_EMPTY = "EMPTY"
STATUS_PERMISSION_DENIED = "PERMISSION DENIED"
STATUS_READ_ERROR = "READ ERROR"
STATUS_UNAVAILABLE = "UNAVAILABLE"


@dataclass
class SnortParseResult:
    """
    Detailed result of parsing a Snort CSV alert file.
    """

    events: List[Event]
    status: str
    error: Optional[str] = None


def parse_endpoint(value):
    """Parse an IP:port endpoint."""

    if not value:
        return None, None

    value = value.strip()

    if ":" not in value:
        return value, None

    host, port = value.rsplit(":", 1)

    try:
        port = int(port)
    except ValueError:
        port = None

    return host, port


def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_snort_csv(path):
    """
    Backward-compatible Snort CSV parser.

    Existing callers continue receiving only a list of events.
    """

    result = parse_snort_csv_with_status(path)

    return result.events


def parse_snort_csv_with_status(path) -> SnortParseResult:
    """
    Parse Snort alert CSV while preserving the actual read/parse
    status for Security Analysis.
    """

    path = Path(path)

    if not path.exists():
        return SnortParseResult(
            events=[],
            status=STATUS_UNAVAILABLE,
            error="Snort alert log does not exist.",
        )

    if not path.is_file():
        return SnortParseResult(
            events=[],
            status=STATUS_UNAVAILABLE,
            error="Snort alert path is not a regular file.",
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
            newline="",
        ) as handle:

            reader = csv.reader(handle)

            events = []

            for line_number, row in enumerate(
                reader,
                start=1,
            ):
                if not row:
                    continue

                if len(row) < len(FIELDS):
                    return SnortParseResult(
                        events=events,
                        status=STATUS_READ_ERROR,
                        error=(
                            f"Invalid Snort CSV row at "
                            f"line {line_number}: expected "
                            f"{len(FIELDS)} fields, got "
                            f"{len(row)}."
                        ),
                    )

                data = dict(
                    zip(
                        FIELDS,
                        row,
                    )
                )

                event = _row_to_event(
                    data,
                )

                if event is not None:
                    events.append(event)

    except PermissionError:
        return SnortParseResult(
            events=[],
            status=STATUS_PERMISSION_DENIED,
            error="Permission denied while reading Snort alerts.",
        )

    except OSError as exc:
        return SnortParseResult(
            events=[],
            status=STATUS_READ_ERROR,
            error=str(exc),
        )

    except csv.Error as exc:
        return SnortParseResult(
            events=[],
            status=STATUS_READ_ERROR,
            error=f"Snort CSV parsing error: {exc}",
        )

    except Exception as exc:
        return SnortParseResult(
            events=[],
            status=STATUS_READ_ERROR,
            error=str(exc),
        )

    if events:
        return SnortParseResult(
            events=events,
            status=STATUS_ANALYZED,
        )

    return SnortParseResult(
        events=[],
        status=STATUS_EMPTY,
    )


def _row_to_event(data) -> Optional[Event]:
    """
    Convert one validated Snort CSV row into a LogViewer Event.
    """

    src_ip, src_port = parse_endpoint(
        data["src_ap"]
    )

    dst_ip, dst_port = parse_endpoint(
        data["dst_ap"]
    )

    priority = safe_int(
        data["priority"]
    )

    if priority is not None:
        if priority <= 1:
            severity = "CRITICAL"
        elif priority == 2:
            severity = "HIGH"
        elif priority == 3:
            severity = "MEDIUM"
        else:
            severity = "INFO"
    else:
        severity = "INFO"

    return Event(
        timestamp=data["timestamp"],
        source="Snort",
        severity=severity,
        message=data["msg"],
        protocol=data["proto"],
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        signature=data["msg"],
        gid=safe_int(data["gid"]),
        sid=safe_int(data["sid"]),
        revision=safe_int(data["rev"]),
        priority=priority,
        action=data["action"],
        raw=data,
    )
