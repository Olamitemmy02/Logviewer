
from pathlib import Path
import os
import stat


# Default system log root
LOG_ROOT = Path("/var/log")

# Files that are not useful for live text-log monitoring
IGNORED_EXTENSIONS = {
    ".gz",
    ".zip",
    ".xz",
    ".bz2",
    ".lz4",
    ".zst",
}

# Prevent very large files from being treated as normal text logs
MAX_LOG_SIZE_MB = 100


def is_regular_file(path: Path) -> bool:
    """Return True only for regular files."""
    try:
        return stat.S_ISREG(path.stat().st_mode)
    except (OSError, PermissionError):
        return False


def is_readable(path: Path) -> bool:
    """Check whether the current process can read the file."""
    try:
        return os.access(path, os.R_OK)
    except OSError:
        return False


def is_probably_text(path: Path) -> bool:
    """
    Perform a lightweight binary-file check.

    Null bytes are treated as an indication that the file
    is probably binary rather than a normal text log.
    """
    try:
        with path.open("rb") as file:
            sample = file.read(4096)

        if not sample:
            return True

        return b"\x00" not in sample

    except (OSError, PermissionError):
        return False


def is_log_file(path: Path) -> bool:
    """Determine whether a file is suitable for LogViewer."""
    try:
        if path.suffix.lower() in IGNORED_EXTENSIONS:
            return False

        if not is_regular_file(path):
            return False

        if not is_readable(path):
            return False

        size_mb = path.stat().st_size / (1024 * 1024)

        if size_mb > MAX_LOG_SIZE_MB:
            return False

        if not is_probably_text(path):
            return False

        return True

    except (OSError, PermissionError):
        return False


def discover_logs(root="/var/log"):
    """
    Recursively discover readable text logs under root.

    Example:
        /var/log/auth.log
        /var/log/syslog
        /var/log/snort/alert_csv.txt
        /var/log/apache2/access.log
    """
    root = Path(root)

    discovered = []

    if not root.exists() or not root.is_dir():
        return discovered

    try:
        for path in root.rglob("*"):
            try:
                if is_log_file(path):
                    discovered.append(path)
            except (OSError, PermissionError):
                continue

    except (OSError, PermissionError):
        return discovered

    return sorted(
        set(discovered),
        key=lambda item: str(item).lower()
    )


def get_log_sources(root="/var/log"):
    """Return discovered logs as strings."""
    return [
        str(path)
        for path in discover_logs(root)
    ]


# ------------------------------------------------------------------
# Compatibility functions
# ------------------------------------------------------------------
# These functions are retained because existing LogViewer modules
# such as viewer.py may import them.
# ------------------------------------------------------------------


def discover_system_logs(root="/var/log"):
    """
    Discover all system logs under /var/log.

    Snort logs are excluded from this function so existing
    system-log views can keep system and Snort sources separate.
    """
    logs = discover_logs(root)

    snort_root = Path(root) / "snort"

    return [
        path
        for path in logs
        if not (
            path == snort_root
            or snort_root in path.parents
        )
    ]


def discover_snort_logs(root="/var/log"):
    """
    Discover Snort logs under /var/log/snort.

    Supports Snort 2 and Snort 3 style log locations.
    """
    root = Path(root)

    snort_directories = [
        root / "snort",
        root / "snort3",
    ]

    discovered = []

    for snort_root in snort_directories:

        if not snort_root.exists():
            continue

        if not snort_root.is_dir():
            continue

        try:
            for path in snort_root.rglob("*"):

                try:
                    if is_log_file(path):
                        discovered.append(path)

                except (OSError, PermissionError):
                    continue

        except (OSError, PermissionError):
            continue

    return sorted(
        set(discovered),
        key=lambda item: str(item).lower()
    )


def get_log_statistics(root="/var/log"):
    """Return discovery statistics."""
    logs = discover_logs(root)

    try:
        total_files = sum(
            1
            for path in Path(root).rglob("*")
            if path.is_file()
        )
    except (OSError, PermissionError):
        total_files = len(logs)

    return {
        "root": str(root),
        "total_files": total_files,
        "readable_logs": len(logs),
        "logs": logs,
    }


def find_log_by_name(name, root="/var/log"):
    """Find a discovered log by filename."""
    name = name.strip().lower()

    for path in discover_logs(root):
        if path.name.lower() == name:
            return path

    return None


def find_logs_containing(pattern, root="/var/log"):
    """
    Find discovered logs whose path contains the supplied pattern.
    """
    pattern = pattern.strip().lower()

    if not pattern:
        return []

    return [
        path
        for path in discover_logs(root)
        if pattern in str(path).lower()
    ]
