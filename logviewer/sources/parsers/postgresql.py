import re
from pathlib import Path
from typing import Optional

from ...events import Event
from .base import LogParser


class PostgreSQLParser(LogParser):
    """
    Parser for PostgreSQL server logs.

    Supported filenames include:

        postgresql-18-main.log
        postgresql-18-main.log.1
        postgresql-18-main.log.2.gz

    Supported records include PostgreSQL startup, shutdown,
    listening, checkpoint, and database-state messages.
    """

    name = "postgresql"

    description = (
        "PostgreSQL server logs including startup, shutdown, "
        "checkpoint, listening, and database state events"
    )

    HEADER = re.compile(
        r"^(?P<timestamp>"
        r"\d{4}-\d{2}-\d{2}"
        r"\s+"
        r"\d{2}:\d{2}:\d{2}"
        r"(?:[.,]\d+)?"
        r")"
        r"\s+"
        r"(?P<timezone>[A-Za-z]{2,8})"
        r"\s+"
        r"\[(?P<pid>\d+)\]"
        r"\s+"
        r"(?P<severity>[A-Z]+)"
        r":"
        r"(?:\s(?P<message>.*))?$"
    )

    VERSION_RE = re.compile(
        r"\bstarting PostgreSQL\s+"
        r"(?P<version>[0-9]+(?:\.[0-9]+)+)"
    )

    LISTENING_RE = re.compile(
        r'^listening on '
        r'(?P<family>IPv4|IPv6) '
        r'address "(?P<address>[^"]+)", '
        r'port (?P<port>\d+)$'
    )

    UNIX_SOCKET_RE = re.compile(
        r'^listening on Unix socket "(?P<socket>[^"]+)"$'
    )

    SHUTDOWN_AT_RE = re.compile(
        r'^database system was shut down at '
        r'(?P<shutdown_time>.+)$'
    )

    CHECKPOINT_RE = re.compile(
        r'^checkpoint '
        r'(?P<phase>starting|complete)'
        r'(?::\s*(?P<details>.*))?$'
    )

    def can_parse(self, path: Path) -> bool:
        """
        Identify PostgreSQL log files, including rotated and
        gzip-compressed variants.
        """

        name = path.name.lower()

        # Remove gzip compression suffix.
        if name.endswith(".gz"):
            name = name[:-3]

        # Accept the normal PostgreSQL log filename.
        if (
            name.startswith("postgresql-")
            and name.endswith(".log")
        ):
            return True

        # Accept numeric rotation:
        #
        # postgresql-18-main.log.1
        # postgresql-18-main.log.2
        # postgresql-18-main.log.10
        rotated_match = re.fullmatch(
            r"postgresql-.+\.log\.\d+",
            name,
        )

        return rotated_match is not None

    def parse_line(
        self,
        line: str,
        source: Path,
    ) -> Optional[Event]:
        """
        Parse one PostgreSQL log record.
        """

        original_line = line.rstrip("\r\n")

        if not original_line.strip():
            return None

        match = self.HEADER.fullmatch(
            original_line
        )

        if not match:
            return Event(
                timestamp="",
                source=str(source),
                severity="INFO",
                message=original_line,
                event_type="postgresql",
                parse_status="unparsed",
                parser=self.name,
                raw={
                    "original_line": original_line,
                    "parse_error": (
                        "unrecognized-postgresql-format"
                    ),
                },
            )

        data = match.groupdict()

        timestamp = data["timestamp"]
        timezone = data["timezone"]
        severity = data["severity"].upper()
        pid = self._to_int(data.get("pid"))
        message = (
            data.get("message") or ""
        ).strip()

        event = Event(
            timestamp=timestamp,
            source=str(source),
            severity=self._normalize_severity(
                severity
            ),
            message=message,
            event_type=self._classify_event(
                message
            ),
            parse_status="parsed",
            parser=self.name,
            pid=pid,
            process="postgres",
            raw={
                "original_line": original_line,
                "timezone": timezone,
            },
        )

        self._extract_version(
            message,
            event,
        )

        self._extract_listening(
            message,
            event,
        )

        self._extract_unix_socket(
            message,
            event,
        )

        self._extract_shutdown_time(
            message,
            event,
        )

        self._extract_checkpoint(
            message,
            event,
        )

        return event

    @staticmethod
    def _classify_event(
        message: str,
    ) -> str:

        lowered = message.lower()

        if lowered.startswith(
            "starting postgresql "
        ):
            return "postgresql_start"

        if lowered.startswith(
            "listening on "
        ):
            return "postgresql_listening"

        if lowered.startswith(
            "database system was shut down"
        ):
            return "postgresql_previous_shutdown"

        if lowered.startswith(
            "database system is ready"
        ):
            return "postgresql_ready"

        if lowered.startswith(
            "received fast shutdown request"
        ):
            return "postgresql_shutdown_request"

        if lowered.startswith(
            "aborting any active transactions"
        ):
            return "postgresql_transaction_abort"

        if lowered.startswith(
            "background worker "
        ):
            return "postgresql_background_worker"

        if lowered == "shutting down":
            return "postgresql_shutdown"

        if lowered.startswith(
            "database system is shut down"
        ):
            return "postgresql_shutdown_complete"

        if lowered.startswith(
            "checkpoint starting"
        ):
            return "postgresql_checkpoint_start"

        if lowered.startswith(
            "checkpoint complete"
        ):
            return "postgresql_checkpoint_complete"

        return "postgresql"

    @staticmethod
    def _normalize_severity(
        severity: str,
    ) -> str:

        mapping = {
            "DEBUG": "DEBUG",
            "INFO": "INFO",
            "LOG": "INFO",
            "NOTICE": "INFO",
            "WARNING": "WARNING",
            "ERROR": "ERROR",
            "FATAL": "CRITICAL",
            "PANIC": "CRITICAL",
        }

        return mapping.get(
            severity.upper(),
            "INFO",
        )

    @classmethod
    def _extract_version(
        cls,
        message: str,
        event: Event,
    ) -> None:

        match = cls.VERSION_RE.search(
            message
        )

        if match:
            event.raw["postgresql_version"] = (
                match.group("version")
            )

    @classmethod
    def _extract_listening(
        cls,
        message: str,
        event: Event,
    ) -> None:

        match = cls.LISTENING_RE.match(
            message
        )

        if not match:
            return

        address = match.group("address")
        port = cls._to_int(
            match.group("port")
        )
        family = match.group("family")

        event.raw["address_family"] = family
        event.raw["listen_address"] = address
        event.raw["listen_port"] = port

        if family == "IPv4":
            event.dst_ip = address
            event.dst_port = port
            event.protocol = "TCP"

    @classmethod
    def _extract_unix_socket(
        cls,
        message: str,
        event: Event,
    ) -> None:

        match = cls.UNIX_SOCKET_RE.match(
            message
        )

        if match:
            event.raw["unix_socket"] = (
                match.group("socket")
            )

    @classmethod
    def _extract_shutdown_time(
        cls,
        message: str,
        event: Event,
    ) -> None:

        match = cls.SHUTDOWN_AT_RE.match(
            message
        )

        if match:
            event.raw["previous_shutdown_time"] = (
                match.group("shutdown_time")
            )

    @classmethod
    def _extract_checkpoint(
        cls,
        message: str,
        event: Event,
    ) -> None:

        match = cls.CHECKPOINT_RE.match(
            message
        )

        if not match:
            return

        event.raw["checkpoint_phase"] = (
            match.group("phase")
        )

        details = match.group("details")

        if details:
            event.raw["checkpoint_details"] = (
                details
            )

    @staticmethod
    def _to_int(
        value,
    ) -> Optional[int]:

        if value is None:
            return None

        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return None
