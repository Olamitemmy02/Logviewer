import csv
from pathlib import Path

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


def parse_endpoint(value):
    """Parse IP:port."""

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
    """Parse Snort alert_csv output into Event objects."""

    path = Path(path)

    if not path.is_file():
        return []

    events = []

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
            newline=""
        ) as handle:

            reader = csv.reader(handle)

            for row in reader:

                if len(row) < len(FIELDS):
                    continue

                data = dict(zip(FIELDS, row))

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

                event = Event(
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

                events.append(event)

    except PermissionError:
        return []

    except OSError:
        return []

    return events
