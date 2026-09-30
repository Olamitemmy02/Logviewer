"""
Shared event normalization and context utilities.

This module provides source-independent helpers for normalized LogViewer
events.

The normalization layer is intentionally non-destructive:

    - It does not modify Event objects.
    - It does not declare events malicious.
    - It does not assign threat scores.
    - It does not perform attribution.
    - It does not reconstruct attack chains.

Its purpose is to provide stable representations that can be reused by
security analysis, IOC extraction, evidence generation, correlation, and
future investigation capabilities.
"""

from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
from typing import Any, Dict, Optional

from logviewer.events import Event


def normalize_optional(
    value: Optional[str],
) -> Optional[str]:
    """
    Normalize an optional value into a stripped string.

    Empty or whitespace-only values become None.
    """

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def normalize_severity(
    value: Optional[str],
) -> str:
    """
    Normalize an event severity value.

    Missing severity defaults to INFO.
    """

    normalized = normalize_optional(value)

    if not normalized:
        return "INFO"

    return normalized.upper()


def normalize_event_type(
    value: Optional[str],
) -> Optional[str]:
    """
    Normalize an event type without changing its semantic or display
    casing.
    """

    return normalize_optional(value)


def normalize_source(
    value: Optional[str],
) -> Optional[str]:
    """
    Normalize an event source identifier.

    Source paths are preserved semantically while surrounding
    whitespace is removed.
    """

    return normalize_optional(value)


def normalize_parser(
    value: Optional[str],
) -> Optional[str]:
    """
    Normalize a parser identifier.
    """

    return normalize_optional(value)


@lru_cache(maxsize=65536)
def _parse_event_timestamp_cached(
    value: str,
) -> Optional[datetime]:
    """
    Cached implementation of timestamp parsing.

    Timestamp strings occur repeatedly across system logs. Caching the
    parsed representation avoids repeatedly executing datetime parsing
    and strptime machinery for identical timestamp values.

    The returned datetime objects are immutable, so returning cached
    instances is safe.
    """

    text = value

    candidates = (
        text,
        text.replace(
            "Z",
            "+00:00",
        ),
    )

    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(
                candidate
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(
                timezone.utc
            )

        except ValueError:
            continue

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
    )

    for timestamp_format in formats:
        try:
            return datetime.strptime(
                text,
                timestamp_format,
            ).replace(
                tzinfo=timezone.utc
            )

        except ValueError:
            continue

    return None


def parse_event_timestamp(
    value: Optional[str],
) -> Optional[datetime]:
    """
    Parse common LogViewer timestamp representations.

    Returned timestamps are normalized to UTC.

    Naive timestamps are interpreted as UTC because LogViewer events
    represent system-log observations and do not currently carry a
    separate timezone field.

    Returns:
        A timezone-aware UTC datetime, or None when parsing fails.
    """

    normalized = normalize_optional(value)

    if not normalized:
        return None

    return _parse_event_timestamp_cached(
        normalized
    )


def normalize_timestamp(
    value: Optional[str],
) -> Optional[str]:
    """
    Normalize a parseable timestamp to an ISO-8601 UTC string.

    When a timestamp cannot be parsed, the original stripped value is
    returned rather than discarded.
    """

    normalized = normalize_optional(value)

    if not normalized:
        return None

    parsed = parse_event_timestamp(
        normalized
    )

    if parsed is None:
        return normalized

    return parsed.isoformat()


def event_text(
    event: Event,
) -> str:
    """
    Build a searchable text representation of an event.

    This preserves the existing LogViewer behavior while providing
    analysis components with a common representation independent
    of the original parser format.
    """

    values = (
        event.message,
        event.command,
        event.process,
        event.file_path,
        event.domain,
        event.url,
        event.src_ip,
        event.dst_ip,
        event.signature,
        event.user,
        event.host,
    )

    return " ".join(
        str(value)
        for value in values
        if value is not None
        and str(value).strip()
    )


def event_context(
    event: Event,
) -> Dict[str, Any]:
    """
    Extract normalized contextual information from an Event.

    The returned dictionary is derived from the normalized Event model.
    It does not modify the event.

    This context is suitable for evidence metadata, correlation,
    investigation displays, and future analytical layers.
    """

    context: Dict[str, Any] = {
        "timestamp": normalize_timestamp(
            event.timestamp
        ),
        "source": normalize_source(
            event.source
        ),
        "severity": normalize_severity(
            event.severity
        ),
        "event_type": normalize_event_type(
            event.event_type
        ),
        "parser": normalize_parser(
            event.parser
        ),
        "parse_status": normalize_optional(
            event.parse_status
        ),
        "host": normalize_optional(
            event.host
        ),
        "user": normalize_optional(
            event.user
        ),
        "protocol": normalize_optional(
            event.protocol
        ),
        "src_ip": normalize_optional(
            event.src_ip
        ),
        "src_port": event.src_port,
        "dst_ip": normalize_optional(
            event.dst_ip
        ),
        "dst_port": event.dst_port,
        "domain": normalize_optional(
            event.domain
        ),
        "url": normalize_optional(
            event.url
        ),
        "process": normalize_optional(
            event.process
        ),
        "pid": event.pid,
        "parent_pid": event.parent_pid,
        "command": normalize_optional(
            event.command
        ),
        "file_path": normalize_optional(
            event.file_path
        ),
        "hash_value": normalize_optional(
            event.hash_value
        ),
        "signature": normalize_optional(
            event.signature
        ),
        "gid": event.gid,
        "sid": event.sid,
        "revision": event.revision,
        "priority": event.priority,
        "action": normalize_optional(
            event.action
        ),
    }

    return {
        key: value
        for key, value in context.items()
        if value is not None
    }


def event_id(
    event: Event,
) -> str:
    """
    Generate a stable event identifier.

    The identity material intentionally preserves the historical
    CorrelationEngine event-ID fields so existing investigation
    references remain compatible.

    This is an identity mechanism only. It is not a security verdict
    and must not be interpreted as proof that two events originated
    from the same real-world activity.
    """

    identity_fields = (
        event.timestamp,
        event.source,
        event.severity,
        event.message,
        event.event_type,
        event.host,
        event.user,
        event.process,
        event.pid,
        event.command,
        event.src_ip,
        event.dst_ip,
        event.src_port,
        event.dst_port,
    )

    material = "\x1f".join(
        str(value or "")
        for value in identity_fields
    )

    return sha256(
        material.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def correlation_keys(
    event: Event,
) -> Dict[str, str]:
    """
    Build stable, source-independent correlation keys.

    This function intentionally does not call event_context().

    Correlation keys only require a small subset of normalized event
    fields. Building the complete event context here caused the
    correlation pipeline to normalize the same event multiple times.

    Keys describe relationships that can be observed from normalized
    event data. They do not assert maliciousness or attribution.

    Only keys with sufficient identifying information are returned.
    """

    source_ip = normalize_optional(
        event.src_ip
    )

    destination_ip = normalize_optional(
        event.dst_ip
    )

    user = normalize_optional(
        event.user
    )

    process = normalize_optional(
        event.process
    )

    file_path = normalize_optional(
        event.file_path
    )

    domain = normalize_optional(
        event.domain
    )

    url = normalize_optional(
        event.url
    )

    hash_value = normalize_optional(
        event.hash_value
    )

    keys: Dict[str, str] = {}

    if source_ip:
        keys["source_ip"] = (
            f"source_ip:{source_ip}"
        )

    if destination_ip:
        keys["destination_ip"] = (
            f"destination_ip:{destination_ip}"
        )

    if source_ip and destination_ip:
        keys["network_pair"] = (
            f"network_pair:{source_ip}->{destination_ip}"
        )

    if user:
        keys["user"] = (
            f"user:{user}"
        )

    if process:
        keys["process"] = (
            f"process:{process}"
        )

    if user and process:
        keys["user_process"] = (
            f"user_process:{user}:{process}"
        )

    if file_path:
        keys["file"] = (
            f"file:{file_path}"
        )

    if domain:
        keys["domain"] = (
            f"domain:{domain}"
        )

    if url:
        keys["url"] = (
            f"url:{url}"
        )

    if hash_value:
        keys["hash"] = (
            f"hash:{hash_value}"
        )

    return keys
