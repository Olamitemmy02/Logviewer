import re
from pathlib import Path
from datetime import datetime

from ...events import Event


# ----------------------------------------------------------------------
# Traditional syslog format
# Example:
# Sep 08 11:35:01 Dave CRON[6981]: pam_unix(cron:session): session opened
# ----------------------------------------------------------------------

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\s:\[]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s*"
    r"(?P<message>.*)$"
)


# ----------------------------------------------------------------------
# ISO-8601 syslog format
# Example:
# 2026-09-08T11:35:01.618710+01:00 Dave CRON[6981]:
# pam_unix(cron:session): session opened
# ----------------------------------------------------------------------

ISO_SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})"
    r")\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\s:\[]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s*"
    r"(?P<message>.*)$"
)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _parse_pid(value):
    """Safely convert a PID value to an integer."""

    if value is None:
        return None

    try:
        return int(value)

    except (TypeError, ValueError):
        return None


def _parse_timestamp(month, day, time_text):
    """
    Convert traditional syslog timestamps into an ISO-like timestamp.

    Traditional syslog entries do not contain a year, so the current
    system year is used.
    """

    try:
        year = datetime.now().year

        value = datetime.strptime(
            f"{year} {month} {day} {time_text}",
            "%Y %b %d %H:%M:%S",
        )

        return value.isoformat(sep=" ")

    except ValueError:
        return f"{month} {day} {time_text}"


def _build_event(
    *,
    timestamp,
    source,
    host,
    process,
    pid,
    message,
    original_line,
    parser_name,
):
    """
    Build a successfully parsed normalized Event.

    Parsing metadata is kept separate from the raw source data so
    downstream Core and Pro components can distinguish parsed events
    from unsupported/unparsed data.
    """

    return Event(
        timestamp=timestamp,
        source=str(source),
        severity="INFO",
        message=message,

        # Parsing metadata
        parse_status="parsed",
        parser=parser_name,

        # Host / process information
        host=host,
        process=process,
        pid=_parse_pid(pid),

        # Preserve original source information
        raw={
            "original_line": original_line,
            "hostname": host,
        },
    )


# ----------------------------------------------------------------------
# Main line parser
# ----------------------------------------------------------------------

def parse_system_line(line, source):
    """
    Parse one system-log line into a normalized Event.

    Supported formats:
        - ISO-8601 syslog
        - Traditional syslog

    Unknown formats are retained as unparsed events so LogViewer can
    report that the source contains data without pretending that the
    data was successfully understood.
    """

    line = line.rstrip("\n")

    if not line.strip():
        return None

    # --------------------------------------------------------------
    # ISO syslog
    # --------------------------------------------------------------

    match = ISO_SYSLOG_PATTERN.match(line)

    if match:
        data = match.groupdict()

        return _build_event(
            timestamp=data["timestamp"],
            source=source,
            host=data["host"],
            process=data["process"],
            pid=data["pid"],
            message=data["message"],
            original_line=line,
            parser_name="iso-syslog",
        )

    # --------------------------------------------------------------
    # Traditional syslog
    # --------------------------------------------------------------

    match = SYSLOG_PATTERN.match(line)

    if match:
        data = match.groupdict()

        timestamp = _parse_timestamp(
            data["month"],
            data["day"],
            data["time"],
        )

        return _build_event(
            timestamp=timestamp,
            source=source,
            host=data["host"],
            process=data["process"],
            pid=data["pid"],
            message=data["message"],
            original_line=line,
            parser_name="syslog",
        )

    # --------------------------------------------------------------
    # Unknown / unsupported format
    # --------------------------------------------------------------

    return Event(
        timestamp="",
        source=str(source),
        severity="INFO",
        message=line,

        # Important: this line was detected but not understood.
        parse_status="unparsed",
        parser="fallback",

        raw={
            "original_line": line,
        },
    )


# ----------------------------------------------------------------------
# File parser
# ----------------------------------------------------------------------

def parse_system_log(path):
    """
    Parse a system log file into normalized Events.

    Returns:
        list[Event]

    Permission errors, missing files, and other OS-level failures
    result in an empty list rather than crashing the application.
    """

    path = Path(path)

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

                event = parse_system_line(
                    line,
                    path,
                )

                if event is not None:
                    events.append(event)

    except (OSError, PermissionError):
        return []

    return events
