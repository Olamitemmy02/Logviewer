import re
from pathlib import Path
from typing import Optional

from ...events import Event
from .base import LogParser


class CrowdSecParser(LogParser):
    """
    Parser for CrowdSec operational and Local API logs.

    Supported sources:

        /var/log/crowdsec.log
        /var/log/crowdsec_api.log

    Rotated and compressed variants are also supported:

        crowdsec.log.1
        crowdsec.log.2.gz
        crowdsec_api.log.1
        crowdsec_api.log.2.gz

    CrowdSec commonly uses a logfmt-style structure such as:

        time="14-09-2026 11:35:10"
        level=info
        msg="Loaded 2 parser nodes"
        file=/etc/crowdsec/parsers/...
        stage=s00-raw

    The parser extracts the common fields while preserving
    additional CrowdSec fields in Event.raw.

    It intentionally does not classify operational CrowdSec
    errors as security threats. Operational state and security
    findings are separate concepts.
    """

    name = "crowdsec"

    description = (
        "CrowdSec engine, parser, acquisition, scenario, "
        "enrichment, and Local API operational events"
    )

    HEADER = re.compile(
        r'^time="(?P<timestamp>[^"]+)"'
        r'\s+level=(?P<level>\S+)'
        r'\s+msg="(?P<message>(?:\\.|[^"\\])*)"'
        r'(?P<fields>(?:\s+\S+=.*)?)$'
    )

    FIELD_PATTERN = re.compile(
        r'(?P<key>[A-Za-z0-9_.-]+)='
        r'(?P<value>'
        r'"(?:\\.|[^"\\])*"'
        r'|'
        r'\S+'
        r')'
    )

    API_REQUEST = re.compile(
        r'^(?P<client>\S+)'
        r'\s+-\s+'
        r'\[(?P<http_timestamp>[^\]]+)\]'
        r'\s+"(?P<method>[A-Z]+)'
        r'\s+(?P<path>\S+)'
        r'\s+HTTP/(?P<http_version>[^"]+)'
        r'\s+(?P<status>\d{3})'
        r'\s+(?P<duration>\S+)'
        r'\s+"(?P<user_agent>[^"]*)"\s*"?$'
    )

    def can_parse(self, path: Path) -> bool:
        """
        Determine whether the source is a CrowdSec log.

        Directory location is deliberately ignored so that the
        parser remains valid if CrowdSec's log directory changes.
        """

        name = path.name.lower()

        if name.endswith(".gz"):
            name = name[:-3]

        if name in {
            "crowdsec.log",
            "crowdsec_api.log",
        }:
            return True

        return bool(
            re.fullmatch(
                r"crowdsec(?:_api)?\.log\.\d+",
                name,
            )
        )

    def parse_line(
        self,
        line: str,
        source: Path,
    ) -> Optional[Event]:
        """
        Parse one CrowdSec log record.

        Records with additional logfmt fields after msg= are
        fully supported.
        """

        original_line = line.rstrip("\r\n")

        if not original_line.strip():
            return None

        normalized_line = original_line.strip()

        match = self.HEADER.fullmatch(
            normalized_line
        )

        if not match:
            return Event(
                timestamp="",
                source=str(source),
                severity="INFO",
                message=normalized_line,
                event_type="crowdsec",
                parse_status="unparsed",
                parser=self.name,
                process="crowdsec",
                raw={
                    "original_line": original_line,
                    "parse_error": (
                        "unrecognized-crowdsec-format"
                    ),
                },
            )

        data = match.groupdict()

        timestamp = (
            data.get("timestamp") or ""
        ).strip()

        level = (
            data.get("level") or "info"
        ).strip().upper()

        message = self._unescape(
            data.get("message") or ""
        ).strip()

        fields = self._parse_fields(
            data.get("fields") or ""
        )

        event_type = self._classify_event(
            message=message,
            source=source,
        )

        raw = {
            "original_line": original_line,
        }

        if fields:
            raw.update(fields)

        api_data = self._parse_api_request(
            message
        )

        if api_data:
            raw.update(api_data)

        action = None
        src_ip = None

        if api_data:
            action = api_data.get("method")
            src_ip = api_data.get("client_ip")

        return Event(
            timestamp=timestamp,
            source=str(source),
            severity=self._normalize_severity(
                level
            ),
            message=message,
            event_type=event_type,
            parse_status="parsed",
            parser=self.name,
            process="crowdsec",
            action=action,
            src_ip=src_ip,
            raw=raw,
        )

    @classmethod
    def _parse_fields(
        cls,
        fields_text: str,
    ) -> dict:
        """
        Parse additional CrowdSec logfmt fields.

        Example:

            file=/etc/crowdsec/scenarios/foo.yaml
            name=crowdsecurity/ssh-bf
            type=file

        Quoted values are unwrapped.
        """

        if not fields_text.strip():
            return {}

        fields = {}

        for match in cls.FIELD_PATTERN.finditer(
            fields_text
        ):
            key = match.group("key")
            value = match.group("value")

            if (
                len(value) >= 2
                and value.startswith('"')
                and value.endswith('"')
            ):
                value = cls._unescape(
                    value[1:-1]
                )

            fields[key] = value

        return fields

    @staticmethod
    def _unescape(value: str) -> str:
        """
        Decode the common escaped characters used by CrowdSec's
        logfmt output.
        """

        return (
            value
            .replace(r"\"", '"')
            .replace(r"\\", "\\")
        )

    @staticmethod
    def _normalize_severity(
        level: str,
    ) -> str:
        """
        Normalize CrowdSec log levels into LogViewer severities.
        """

        level = level.upper()

        mapping = {
            "TRACE": "DEBUG",
            "DEBUG": "DEBUG",
            "INFO": "INFO",
            "NOTICE": "INFO",
            "WARNING": "WARNING",
            "WARN": "WARNING",
            "ERROR": "ERROR",
            "ERR": "ERROR",
            "CRITICAL": "CRITICAL",
            "CRIT": "CRITICAL",
            "FATAL": "CRITICAL",
            "PANIC": "CRITICAL",
        }

        return mapping.get(
            level,
            "INFO",
        )

    @staticmethod
    def _classify_event(
        message: str,
        source: Path,
    ) -> str:
        """
        Classify CrowdSec operational events.

        This classification describes what CrowdSec was doing.
        It does not claim that the event represents an attack.
        """

        source_name = source.name.lower()
        text = message.lower()

        if "api" in source_name:
            if (
                "http/" in text
                or "get /" in text
                or "post /" in text
                or "put /" in text
                or "delete /" in text
                or "patch /" in text
            ):
                return "api_request"

            return "api"

        if (
            "shutting down" in text
            or "engine shutting down" in text
        ):
            return "shutdown"

        if (
            "starting" in text
            or "start " in text
        ):
            return "startup"

        if (
            "loading" in text
            or "loaded" in text
        ):
            return "configuration"

        if (
            "datasource" in text
            or "data source" in text
        ):
            return "acquisition"

        if "scenario" in text:
            return "scenario"

        if "parser" in text:
            return "parser"

        if (
            "capi" in text
            or "central api" in text
        ):
            return "central_api"

        if (
            "plugin" in text
            or "enricher" in text
            or "enrichment" in text
        ):
            return "enrichment"

        return "operational"

    @classmethod
    def _parse_api_request(
        cls,
        message: str,
    ) -> dict:
        """
        Extract HTTP information from CrowdSec Local API messages.

        Returns an empty dictionary when the message is not an
        API request.
        """

        match = cls.API_REQUEST.fullmatch(
            message.strip()
        )

        if not match:
            return {}

        data = match.groupdict()

        client = (
            data.get("client") or ""
        ).strip()

        client_ip = client

        if (
            client.startswith("[")
            and "]" in client
        ):
            client_ip = client[
                1:
            ].split(
                "]",
                1,
            )[0]

        elif (
            ":" in client
            and client.count(":") == 1
        ):
            client_ip = client.rsplit(
                ":",
                1,
            )[0]

        return {
            "api_client": client,
            "client_ip": client_ip,
            "http_timestamp": data.get(
                "http_timestamp"
            ),
            "method": data.get(
                "method"
            ),
            "path": data.get(
                "path"
            ),
            "http_version": data.get(
                "http_version"
            ),
            "status_code": cls._to_int(
                data.get("status")
            ),
            "duration": data.get(
                "duration"
            ),
            "user_agent": data.get(
                "user_agent"
            ),
        }

    @staticmethod
    def _to_int(value):
        if value is None:
            return None

        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return None
