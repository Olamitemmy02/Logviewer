from pathlib import Path

from .parser import (
    STATUS_EMPTY,
    STATUS_PERMISSION_DENIED,
    STATUS_READ_ERROR,
    STATUS_UNAVAILABLE,
    parse_snort_csv,
    parse_snort_csv_with_status,
)


DEFAULT_SNORT_LOG = "/var/log/snort/alert_csv.txt"


def get_snort_log():
    """
    Return the first available Snort CSV log.
    """

    candidates = [
        "/var/log/snort/alert_csv.txt",
        "/var/log/snort3/alert_csv.txt",
    ]

    for path in candidates:
        if Path(path).is_file():
            return path

    return None


def read_snort_events():
    """
    Backward-compatible Snort event reader.

    Existing callers continue receiving only a list of events.
    """

    path = get_snort_log()

    if not path:
        return []

    return parse_snort_csv(path)


def read_snort_events_with_status():
    """
    Read Snort alerts while preserving the actual source status.
    """

    path = get_snort_log()

    if not path:
        return {
            "events": [],
            "status": STATUS_UNAVAILABLE,
            "path": None,
            "error": "No supported Snort alert CSV was found.",
        }

    snort_path = Path(path)

    if not snort_path.is_file():
        return {
            "events": [],
            "status": STATUS_UNAVAILABLE,
            "path": str(snort_path),
            "error": "Snort alert path is not a regular file.",
        }

    try:
        with snort_path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ):
            pass

    except PermissionError:
        return {
            "events": [],
            "status": STATUS_PERMISSION_DENIED,
            "path": str(snort_path),
            "error": "Permission denied while reading Snort alerts.",
        }

    except OSError as exc:
        return {
            "events": [],
            "status": STATUS_READ_ERROR,
            "path": str(snort_path),
            "error": str(exc),
        }

    result = parse_snort_csv_with_status(
        snort_path,
    )

    return {
        "events": result.events,
        "status": result.status,
        "path": str(snort_path),
        "error": result.error,
    }
