from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class Event:
    """
    Normalized event used throughout LogViewer.

    The model supports Core log viewing and future Pro investigation
    capabilities while preserving source-specific information.

    Parsing metadata allows LogViewer to distinguish between:
        - parsed events
        - partially parsed events
        - unparsed/fallback entries
    """

    # ------------------------------------------------------------------
    # Core event identity
    # ------------------------------------------------------------------

    timestamp: str
    source: str
    severity: str = "INFO"
    message: str = ""
    event_type: Optional[str] = None

    # ------------------------------------------------------------------
    # Parsing metadata
    # ------------------------------------------------------------------

    parse_status: str = "parsed"
    parser: Optional[str] = None

    # ------------------------------------------------------------------
    # Host / identity context
    # ------------------------------------------------------------------

    host: Optional[str] = None
    user: Optional[str] = None

    # ------------------------------------------------------------------
    # Network information
    # ------------------------------------------------------------------

    protocol: Optional[str] = None

    src_ip: Optional[str] = None
    src_port: Optional[int] = None

    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None

    domain: Optional[str] = None
    url: Optional[str] = None

    # ------------------------------------------------------------------
    # Process information
    # ------------------------------------------------------------------

    process: Optional[str] = None
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    command: Optional[str] = None

    # ------------------------------------------------------------------
    # File / artifact information
    # ------------------------------------------------------------------

    file_path: Optional[str] = None
    hash_value: Optional[str] = None

    # ------------------------------------------------------------------
    # Detection / security information
    # ------------------------------------------------------------------

    signature: Optional[str] = None

    gid: Optional[int] = None
    sid: Optional[int] = None
    revision: Optional[int] = None
    priority: Optional[int] = None

    action: Optional[str] = None

    # ------------------------------------------------------------------
    # Original source-specific information
    # ------------------------------------------------------------------

    raw: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def as_dict(self) -> Dict[str, Any]:
        """
        Return the event as a dictionary.

        Includes both normalized fields and parsing metadata so that
        exported investigations retain information about how the event
        was interpreted.
        """

        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity,
            "message": self.message,
            "event_type": self.event_type,

            # Parsing metadata
            "parse_status": self.parse_status,
            "parser": self.parser,

            # Host / identity
            "host": self.host,
            "user": self.user,

            # Network
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "domain": self.domain,
            "url": self.url,

            # Process
            "process": self.process,
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "command": self.command,

            # File / artifact
            "file_path": self.file_path,
            "hash_value": self.hash_value,

            # Detection / security
            "signature": self.signature,
            "gid": self.gid,
            "sid": self.sid,
            "revision": self.revision,
            "priority": self.priority,
            "action": self.action,

            # Original source-specific data
            "raw": self.raw,
        }

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    @property
    def source_endpoint(self) -> str:
        """Return the source IP and port as a readable endpoint."""

        if not self.src_ip:
            return "-"

        if self.src_port is None:
            return self.src_ip

        return f"{self.src_ip}:{self.src_port}"

    @property
    def destination_endpoint(self) -> str:
        """Return the destination IP and port as a readable endpoint."""

        if not self.dst_ip:
            return "-"

        if self.dst_port is None:
            return self.dst_ip

        return f"{self.dst_ip}:{self.dst_port}"
