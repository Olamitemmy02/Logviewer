import re
from pathlib import Path
from typing import Optional

from .base import LogParser
from ...events import Event


# ----------------------------------------------------------------------
# Maltrail log format
#
# Example:
#
# "2026-08-03 10:45:57.019738" CyberRed 10.0.2.9 33595
# 10.187.115.77 53 UDP DNS ip-api.com
# "ipinfo (suspicious)" (static)
# ----------------------------------------------------------------------

MALTRAIL_PATTERN = re.compile(
    r'^"(?P<timestamp>'
    r'\d{4}-\d{2}-\d{2}'
    r'\s+'
    r'\d{2}:\d{2}:\d{2}'
    r'(?:\.\d+)?'
    r')"'
    r'\s+'
    r'(?P<host>\S+)'
    r'\s+'
    r'(?P<src_ip>\S+)'
    r'\s+'
    r'(?P<src_port>\d+)'
    r'\s+'
    r'(?P<dst_ip>\S+)'
    r'\s+'
    r'(?P<dst_port>\d+)'
    r'\s+'
    r'(?P<protocol>\S+)'
    r'\s+'
    r'(?P<service>\S+)'
    r'\s+'
    r'(?P<domain>\S+)'
    r'\s+'
    r'"(?P<detection>[^"]*)"'
    r'\s+'
    r'\((?P<classification>[^)]*)\)'
    r'\s*$'
)


class MaltrailParser(LogParser):
    """
    Parser for Maltrail network detection logs.

    Converts Maltrail entries into normalized LogViewer Events.
    """

    name = "maltrail"
    description = "Maltrail network detection logs"

    def can_parse(self, path: Path) -> bool:
        """
        Determine whether this parser supports the given source.
        """

        normalized = str(path).lower()

        return (
            path.is_file()
            and "maltrail" in normalized
            and path.suffix.lower() == ".log"
        )

    def parse_line(
        self,
        line: str,
        source: Path,
    ) -> Optional[Event]:
        """
        Parse one Maltrail detection entry.
        """

        line = line.rstrip("\n")

        if not line.strip():
            return None

        match = MALTRAIL_PATTERN.match(line)

        if not match:
            return Event(
                timestamp="",
                source=str(source),
                severity="INFO",
                message=line,
                parse_status="unparsed",
                parser=self.name,
                raw={
                    "original_line": line,
                },
            )

        data = match.groupdict()

        detection = data["detection"].strip()
        classification = data["classification"].strip()

        severity = self._determine_severity(
            detection,
            classification,
        )

        event_type = self._determine_event_type(
            data["service"],
            detection,
        )

        return Event(
            timestamp=data["timestamp"],
            source=str(source),
            severity=severity,
            message=detection or "Maltrail detection",
            event_type=event_type,
            parse_status="parsed",
            parser=self.name,

            # Host information
            host=data["host"],

            # Network information
            protocol=data["protocol"],
            src_ip=data["src_ip"],
            src_port=self._safe_int(data["src_port"]),
            dst_ip=data["dst_ip"],
            dst_port=self._safe_int(data["dst_port"]),
            domain=data["domain"],

            # Detection information
            signature=detection or None,
            action="detected",

            # Preserve Maltrail-specific information
            raw={
                "original_line": line,
                "service": data["service"],
                "detection": detection,
                "classification": classification,
            },
        )

    @staticmethod
    def _safe_int(value: Optional[str]) -> Optional[int]:
        """
        Safely convert a value to an integer.
        """

        try:
            return int(value)

        except (TypeError, ValueError):
            return None

    @staticmethod
    def _determine_severity(
        detection: str,
        classification: str,
    ) -> str:
        """
        Map Maltrail detection/classification information to an
        initial LogViewer severity.

        This is a classification mapping, not a certainty that
        the activity is malicious.
        """

        combined = (
            f"{detection} {classification}"
        ).lower()

        if any(
            keyword in combined
            for keyword in (
                "critical",
                "malicious",
                "attack",
            )
        ):
            return "HIGH"

        if any(
            keyword in combined
            for keyword in (
                "suspicious",
                "warning",
            )
        ):
            return "MEDIUM"

        return "INFO"

    @staticmethod
    def _determine_event_type(
        service: str,
        detection: str,
    ) -> str:
        """
        Determine a broad category for the Maltrail event.
        """

        service_lower = service.lower()
        detection_lower = detection.lower()

        if service_lower == "dns":
            if "suspicious" in detection_lower:
                return "suspicious_dns"

            return "dns_activity"

        if "http" in service_lower:
            return "http_activity"

        if "scan" in detection_lower:
            return "network_scan"

        if "suspicious" in detection_lower:
            return "suspicious_network_activity"

        return "network_detection"
