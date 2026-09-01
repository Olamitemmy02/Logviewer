from pathlib import Path

from .parser import parse_snort_csv


DEFAULT_SNORT_LOG = "/var/log/snort/alert_csv.txt"


def get_snort_log():
    """Return the first available Snort CSV log."""

    candidates = [
        "/var/log/snort/alert_csv.txt",
        "/var/log/snort3/alert_csv.txt",
    ]

    for path in candidates:

        if Path(path).is_file():
            return path

    return None


def read_snort_events():
    """Read current Snort events from the real system."""

    path = get_snort_log()

    if not path:
        return []

    return parse_snort_csv(path)
