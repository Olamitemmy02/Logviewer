import re
from pathlib import Path
from typing import Dict, Optional

from ...events import Event
from .base import LogParser


class UfwParser(LogParser):
    """
    Parser for Linux UFW firewall log records.

    Supported examples:

        /var/log/ufw.log
        /var/log/ufw.log.1
        /var/log/ufw.log.2.gz

    The parser normalizes common firewall fields into the shared Event
    model while preserving the original packet metadata in Event.raw.

    Supported UFW actions include:

        UFW BLOCK
        UFW ALLOW
        UFW AUDIT
    """

    name = "ufw"

    description = (
        "Linux UFW firewall events with normalized network endpoints, "
        "protocols, actions, interfaces, and packet metadata"
    )

    HEADER = re.compile(
        r"^(?P<timestamp>"
        r"\d{4}-\d{2}-\d{2}"
        r"T"
        r"\d{2}:\d{2}:\d{2}"
        r"(?:[.,]\d+)?"
        r"(?:Z|[+-]\d{2}:\d{2})?"
        r")"
        r"\s+"
        r"(?P<host>\S+)"
        r"\s+"
        r"(?P<process>\S+)"
        r":\s+"
        r"\[UFW\s+(?P<action>BLOCK|ALLOW|AUDIT)\]"
        r"(?P<body>.*)$",
        re.IGNORECASE,
    )

    ROTATED_SUFFIX = re.compile(
        r"^ufw\.log(?:\.\d+)?(?:\.gz)?$",
        re.IGNORECASE,
    )

    FIELD_PATTERN = re.compile(
        r"(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>\S*)"
    )

    FLAG_PATTERN = re.compile(
        r"(?<!\S)"
        r"(?P<flag>"
        r"DF|MF|RES|ACK|PSH|RST|SYN|FIN|URG|ECE|CWR"
        r")"
        r"(?!\S)"
    )

    def can_parse(self, path: Path) -> bool:
        """
        Return True for UFW log files and their rotated/compressed forms.
        """

        name = path.name.lower()

        return bool(self.ROTATED_SUFFIX.fullmatch(name))

    def parse_line(
        self,
        line: str,
        source: Path,
    ) -> Optional[Event]:
        """
        Parse one UFW firewall record into a normalized Event.
        """

        original_line = line.rstrip("\r\n")

        if not original_line.strip():
            return None

        match = self.HEADER.fullmatch(original_line)

        if not match:
            return Event(
                timestamp="",
                source=str(source),
                severity="INFO",
                message=original_line,
                event_type="ufw",
                parse_status="unparsed",
                parser=self.name,
                raw={
                    "original_line": original_line,
                    "parse_error": "unrecognized-ufw-format",
                },
            )

        data = match.groupdict()

        timestamp = data["timestamp"]
        host = data.get("host")
        process = data.get("process")
        action = data.get("action", "").upper()
        body = (data.get("body") or "").strip()

        fields = self._parse_fields(body)
        flags = self._parse_flags(body)

        src_ip = self._normalize_value(fields.get("SRC"))
        dst_ip = self._normalize_value(fields.get("DST"))

        src_port = self._to_int(fields.get("SPT"))
        dst_port = self._to_int(fields.get("DPT"))

        protocol = self._normalize_value(
            fields.get("PROTO")
        )

        interface = self._normalize_value(
            fields.get("IN")
        )

        output_interface = self._normalize_value(
            fields.get("OUT")
        )

        severity = self._severity_for_action(action)

        raw: Dict[str, object] = {
            "original_line": original_line,
            "ufw_action": action,
            "interface": interface,
            "output_interface": output_interface,
            "fields": fields,
            "flags": flags,
        }

        if process:
            raw["process"] = process

        return Event(
            timestamp=timestamp,
            source=str(source),
            severity=severity,
            message=f"UFW {action}",
            event_type="ufw",
            parse_status="parsed",
            parser=self.name,
            host=host,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            action=action.lower(),
            signature=f"UFW {action}",
            raw=raw,
        )

    @classmethod
    def _parse_fields(cls, body: str) -> Dict[str, str]:
        """
        Extract key=value packet fields.

        UFW values are normally whitespace-delimited, which makes this
        approach suitable for the kernel firewall records observed on
        the target system.
        """

        fields: Dict[str, str] = {}

        for match in cls.FIELD_PATTERN.finditer(body):
            key = match.group("key")
            value = match.group("value")

            fields[key] = value

        return fields

    @classmethod
    def _parse_flags(cls, body: str):
        """
        Extract packet flags that appear without an '=' value.

        Examples:

            DF
            ACK
            PSH
            URGP=0

        Only standalone known flags are captured here.
        """

        flags = []

        for match in cls.FLAG_PATTERN.finditer(body):
            flag = match.group("flag")

            if flag not in flags:
                flags.append(flag)

        return flags

    @staticmethod
    def _normalize_value(value: Optional[str]):
        if value is None:
            return None

        value = str(value).strip()

        if not value:
            return None

        return value

    @staticmethod
    def _to_int(value: Optional[str]):
        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _severity_for_action(action: str) -> str:
        """
        Map UFW actions to LogViewer severity.

        BLOCK and AUDIT are security-relevant firewall events.
        ALLOW represents permitted traffic and is therefore INFO.
        """

        action = action.upper()

        if action == "BLOCK":
            return "WARNING"

        if action == "AUDIT":
            return "WARNING"

        return "INFO"
