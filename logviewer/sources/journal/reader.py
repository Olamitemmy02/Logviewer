import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from ...events import Event


JOURNALCTL = "journalctl"


STATUS_ANALYZED = "ANALYZED"
STATUS_EMPTY = "EMPTY"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_PERMISSION_DENIED = "PERMISSION DENIED"
STATUS_READ_ERROR = "READ ERROR"


@dataclass
class JournalReadResult:
    """
    Detailed result of a systemd journal read operation.

    This allows Security Analysis to distinguish an actually empty
    journal from a journal that could not be accessed or read.
    """

    events: List[Event]
    status: str
    error: Optional[str] = None


class JournalReader:
    """
    Read systemd journal entries through journalctl.

    The journal is a binary data store, so LogViewer intentionally
    does not parse .journal files directly. journalctl provides the
    supported interface and structured JSON records.
    """

    def __init__(
        self,
        journalctl_path: str = JOURNALCTL,
    ):
        self.journalctl_path = journalctl_path

    def read(
        self,
        limit: Optional[int] = 1000,
    ) -> List[Event]:
        """
        Backward-compatible journal reader.

        Existing LogViewer callers continue receiving only a list
        of events.
        """

        result = self.read_with_status(
            limit=limit,
        )

        return result.events

    def read_with_status(
        self,
        limit: Optional[int] = 1000,
    ) -> JournalReadResult:
        """
        Read the systemd journal and preserve the actual read status.
        """

        command = self._build_command(
            limit=limit,
        )

        return self._execute(
            command,
        )

    def read_since(
        self,
        since: str,
        limit: Optional[int] = 1000,
    ) -> List[Event]:
        """
        Backward-compatible journal reader for time-filtered reads.
        """

        result = self.read_since_with_status(
            since=since,
            limit=limit,
        )

        return result.events

    def read_since_with_status(
        self,
        since: str,
        limit: Optional[int] = 1000,
    ) -> JournalReadResult:
        """
        Read journal entries since a specified time while preserving
        the actual read status.
        """

        command = self._build_command(
            limit=limit,
            since=since,
        )

        return self._execute(
            command,
        )

    def _build_command(
        self,
        limit: Optional[int] = 1000,
        since: Optional[str] = None,
    ) -> List[str]:
        command = [
            self.journalctl_path,
            "--no-pager",
            "--quiet",
            "-o",
            "json",
        ]

        if since:
            command.extend(
                [
                    "--since",
                    since,
                ]
            )

        if limit is not None:
            command.extend(
                [
                    "-n",
                    str(limit),
                ]
            )

        return command

    def _execute(
        self,
        command: List[str],
    ) -> JournalReadResult:
        """
        Execute journalctl and convert its result into a structured
        status.

        Important:
        An empty stdout with return code 0 means EMPTY.

        A non-zero return code means READ ERROR or
        PERMISSION DENIED depending on the error message.
        """

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )

        except FileNotFoundError:
            return JournalReadResult(
                events=[],
                status=STATUS_UNAVAILABLE,
                error=(
                    f"journalctl executable not found: "
                    f"{self.journalctl_path}"
                ),
            )

        except PermissionError:
            return JournalReadResult(
                events=[],
                status=STATUS_PERMISSION_DENIED,
                error="Permission denied while executing journalctl.",
            )

        except OSError as exc:
            return JournalReadResult(
                events=[],
                status=STATUS_READ_ERROR,
                error=str(exc),
            )

        except subprocess.SubprocessError as exc:
            return JournalReadResult(
                events=[],
                status=STATUS_READ_ERROR,
                error=str(exc),
            )

        stderr = (
            result.stderr.strip()
            if result.stderr
            else ""
        )

        if result.returncode != 0:
            status = self._status_from_error(
                stderr,
            )

            return JournalReadResult(
                events=[],
                status=status,
                error=stderr or (
                    f"journalctl exited with "
                    f"status {result.returncode}"
                ),
            )

        events = self.parse_json_lines(
            result.stdout.splitlines()
        )

        if events:
            return JournalReadResult(
                events=events,
                status=STATUS_ANALYZED,
            )

        return JournalReadResult(
            events=[],
            status=STATUS_EMPTY,
        )

    @staticmethod
    def _status_from_error(
        error: str,
    ) -> str:
        """
        Classify journalctl errors without guessing based on
        event count.
        """

        normalized = error.lower()

        permission_indicators = (
            "permission denied",
            "access denied",
            "not permitted",
            "authentication is required",
            "failed to open",
        )

        if any(
            indicator in normalized
            for indicator in permission_indicators
        ):
            return STATUS_PERMISSION_DENIED

        return STATUS_READ_ERROR

    @classmethod
    def parse_json_lines(
        cls,
        lines: Iterable[str],
    ) -> List[Event]:
        events = []

        for line in lines:
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(record, dict):
                continue

            event = cls.record_to_event(
                record,
            )

            if event is not None:
                events.append(event)

        return events

    @classmethod
    def record_to_event(
        cls,
        record: Dict,
    ) -> Optional[Event]:
        message = cls._string_value(
            record.get("MESSAGE")
        )

        timestamp = cls._timestamp_from_record(
            record
        )

        hostname = cls._string_value(
            record.get("_HOSTNAME")
        )

        process = cls._string_value(
            record.get("_COMM")
        )

        executable = cls._string_value(
            record.get("_EXE")
        )

        command = cls._string_value(
            record.get("_CMDLINE")
        )

        pid = cls._integer_value(
            record.get("_PID")
            or record.get("SYSLOG_PID")
        )

        uid = cls._string_value(
            record.get("_UID")
        )

        gid = cls._integer_value(
            record.get("_GID")
        )

        priority = cls._integer_value(
            record.get("PRIORITY")
        )

        unit = cls._string_value(
            record.get("_SYSTEMD_UNIT")
            or record.get("UNIT")
        )

        severity = cls._severity_from_priority(
            priority
        )

        event_type = (
            unit
            or cls._string_value(
                record.get("SYSLOG_IDENTIFIER")
            )
        )

        return Event(
            timestamp=timestamp,
            source="systemd-journal",
            severity=severity,
            message=message or "",
            event_type=event_type,
            parse_status="parsed",
            parser="systemd-journal-json",
            host=hostname,
            user=uid,
            process=process,
            pid=pid,
            command=command,
            file_path=executable,
            gid=gid,
            priority=priority,
            raw={
                "journal": record,
            },
        )

    @staticmethod
    def _string_value(
        value,
    ) -> Optional[str]:
        if value is None:
            return None

        value = str(value).strip()

        return value or None

    @staticmethod
    def _integer_value(
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

    @staticmethod
    def _timestamp_from_record(
        record: Dict,
    ) -> str:
        """
        Convert journald's microsecond timestamp into an
        ISO-8601 timestamp using the system's local timezone.
        """

        value = record.get(
            "__REALTIME_TIMESTAMP"
        )

        if value is None:
            return ""

        try:
            microseconds = int(value)

            timestamp = datetime.fromtimestamp(
                microseconds / 1_000_000,
                tz=timezone.utc,
            )

            local_timestamp = timestamp.astimezone()

            return local_timestamp.isoformat()

        except (
            TypeError,
            ValueError,
            OverflowError,
            OSError,
        ):
            return ""

    @staticmethod
    def _severity_from_priority(
        priority: Optional[int],
    ) -> str:
        mapping = {
            0: "CRITICAL",
            1: "CRITICAL",
            2: "CRITICAL",
            3: "ERROR",
            4: "WARNING",
            5: "NOTICE",
            6: "INFO",
            7: "DEBUG",
        }

        return mapping.get(
            priority,
            "INFO",
        )
