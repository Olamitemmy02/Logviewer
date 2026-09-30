import re
from pathlib import Path
from typing import Optional

from .base import LogParser
from ...events import Event


ERROR_LOG_PATTERN = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+"
    r"\[(?P<module>[^:\]]+):(?P<severity>[^\]]+)\]\s+"
    r"\[pid\s+(?P<pid>\d+)"
    r"(?:\:tid\s+(?P<tid>\d+))?\]\s+"
    r"(?P<message>.*)$"
)


MPROTECT_PATTERN = re.compile(
    r"^mprotect\(\)\s+failed\s+\[(?P<errno>\d+)\]\s+"
    r"(?P<reason>.+)$",
    re.IGNORECASE,
)


ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+'
    r'(?P<url>\S+)'
    r'(?:\s+(?P<protocol>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
    r'\s*$'
)


class ApacheParser(LogParser):
    name = "apache"
    description = "Apache HTTP server access and error logs"

    def can_parse(self, path: Path) -> bool:
        normalized = str(path).lower()

        return (
            path.is_file()
            and (
                normalized.endswith("/apache2/error.log")
                or normalized.endswith("/apache2/access.log")
            )
        )

    def parse_line(
        self,
        line: str,
        source: Path,
    ) -> Optional[Event]:

        line = line.rstrip("\n")

        if not line.strip():
            return None

        filename = source.name.lower()

        if filename == "error.log":
            return self._parse_error(line, source)

        if filename == "access.log":
            return self._parse_access(line, source)

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

    def _parse_error(
        self,
        line: str,
        source: Path,
    ) -> Event:

        match = ERROR_LOG_PATTERN.match(line)

        if match:
            data = match.groupdict()

            severity = self._normalize_severity(
                data["severity"]
            )

            return Event(
                timestamp=data["timestamp"],
                source=str(source),
                severity=severity,
                message=data["message"],
                event_type="apache_error",
                parse_status="parsed",
                parser=self.name,
                process=data["module"],
                pid=self._safe_int(data["pid"]),
                raw={
                    "original_line": line,
                    "log_type": "error",
                    "module": data["module"],
                    "apache_severity": data["severity"],
                    "thread_id": self._safe_int(data["tid"]),
                },
            )

        mprotect_match = MPROTECT_PATTERN.match(line)

        if mprotect_match:
            data = mprotect_match.groupdict()

            return Event(
                timestamp="",
                source=str(source),
                severity="WARNING",
                message=line,
                event_type="apache_startup_warning",
                parse_status="parsed",
                parser=self.name,
                action="permission_denied",
                raw={
                    "original_line": line,
                    "log_type": "error",
                    "error_type": "mprotect_failure",
                    "errno": self._safe_int(data["errno"]),
                    "reason": data["reason"],
                },
            )

        return Event(
            timestamp="",
            source=str(source),
            severity="INFO",
            message=line,
            parse_status="unparsed",
            parser=self.name,
            raw={
                "original_line": line,
                "log_type": "error",
            },
        )

    def _parse_access(
        self,
        line: str,
        source: Path,
    ) -> Event:

        match = ACCESS_LOG_PATTERN.match(line)

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
                    "log_type": "access",
                },
            )

        data = match.groupdict()

        status = self._safe_int(data["status"])

        severity = self._access_severity(status)

        message = (
            f'{data["method"]} '
            f'{data["url"]} '
            f'HTTP {data["status"]}'
        )

        return Event(
            timestamp=data["timestamp"],
            source=str(source),
            severity=severity,
            message=message,
            event_type="http_request",
            parse_status="parsed",
            parser=self.name,
            protocol=data["protocol"],
            src_ip=data["client_ip"],
            url=data["url"],
            action=data["method"],
            raw={
                "original_line": line,
                "log_type": "access",
                "http_method": data["method"],
                "http_status": status,
                "response_size": data["size"],
                "referrer": data["referrer"],
                "user_agent": data["user_agent"],
            },
        )

    @staticmethod
    def _safe_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_severity(value: str) -> str:
        severity = value.lower()

        mapping = {
            "emerg": "CRITICAL",
            "alert": "CRITICAL",
            "crit": "CRITICAL",
            "error": "ERROR",
            "warn": "WARNING",
            "notice": "INFO",
            "info": "INFO",
            "debug": "DEBUG",
        }

        return mapping.get(
            severity,
            severity.upper(),
        )

    @staticmethod
    def _access_severity(
        status: Optional[int],
    ) -> str:

        if status is None:
            return "INFO"

        if status >= 500:
            return "ERROR"

        if status >= 400:
            return "WARNING"

        return "INFO"
