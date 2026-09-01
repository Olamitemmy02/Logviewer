SNORT_LOG_FILE = "/var/log/snort/alert_csv.txt"

SNORT_FIELDS = [
    "timestamp",
    "gid",
    "sid",
    "rev",
    "priority",
    "message",
    "protocol",
    "source",
    "destination",
    "rule",
    "action",
]

MAX_RECENT_ALERTS = 20
