from pathlib import Path
from typing import Dict, List

from .sources.classification import SourceClassifier


DEFAULT_LOG_ROOT = Path("/var/log")
SNORT_ROOTS = (
    Path("/var/log/snort"),
    Path("/var/log/snort3"),
)


def discover_logs(root=DEFAULT_LOG_ROOT) -> List[Path]:
    """
    Discover files under the supplied log directory.

    Directories are not returned.

    Backup and rotated files are still discovered. Their final
    classification is handled by SourceClassifier.
    """
    root = Path(root)

    if not root.exists() or not root.is_dir():
        return []

    logs = []

    try:
        for path in root.rglob("*"):
            if not path.is_file():
                continue

            try:
                if path.is_symlink():
                    continue
            except OSError:
                continue

            logs.append(path)

    except (OSError, PermissionError):
        return []

    return sorted(
        logs,
        key=lambda path: str(path).lower(),
    )


def discover_sources(root=DEFAULT_LOG_ROOT):
    """
    Discover and classify system log sources.

    Returns:
        List[SourceInfo]
    """
    paths = discover_logs(root)

    classifier = SourceClassifier()

    return classifier.classify_many(paths)


def discover_system_logs(root=DEFAULT_LOG_ROOT) -> List[Path]:
    """
    Compatibility interface for existing Core features.

    Returns discovered system log files while preserving the
    existing search/viewer API.

    Classification is intentionally not applied here because
    existing callers expect paths rather than SourceInfo objects.
    """
    return discover_logs(root)


def discover_snort_logs() -> List[Path]:
    """
    Discover existing Snort log files.

    Only real files on the host are returned. No test or example
    data is created or substituted.
    """
    logs = []

    for root in SNORT_ROOTS:
        if not root.exists() or not root.is_dir():
            continue

        try:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue

                try:
                    if path.is_symlink():
                        continue
                except OSError:
                    continue

                logs.append(path)

        except (OSError, PermissionError):
            continue

    return sorted(
        set(logs),
        key=lambda path: str(path).lower(),
    )


def get_log_statistics(root=DEFAULT_LOG_ROOT) -> Dict:
    """
    Return structured statistics about discovered log sources.
    """
    sources = discover_sources(root)

    status_counts = {
        "SUPPORTED": 0,
        "PARTIAL": 0,
        "UNSUPPORTED": 0,
        "EMPTY": 0,
        "UNREADABLE": 0,
        "BACKUP": 0,
        "ROTATED": 0,
        "DIRECTORY": 0,
    }

    for source in sources:
        if source.status in status_counts:
            status_counts[source.status] += 1

    supported = [
        source
        for source in sources
        if source.status == "SUPPORTED"
    ]

    analyzable = [
        source
        for source in sources
        if source.is_analyzable
    ]

    return {
        "root": str(root),
        "logs": [
            source.path
            for source in sources
        ],
        "sources": sources,
        "total": len(sources),
        "supported": len(supported),
        "analyzable": len(analyzable),
        "status_counts": status_counts,
    }
