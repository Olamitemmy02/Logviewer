from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class Event:
    """Normalized event used throughout LogViewer."""

    timestamp: str
    source: str
    severity: str = "INFO"
    message: str = ""

    protocol: Optional[str] = None

    src_ip: Optional[str] = None
    src_port: Optional[int] = None

    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None

    signature: Optional[str] = None

    gid: Optional[int] = None
    sid: Optional[int] = None
    revision: Optional[int] = None
    priority: Optional[int] = None

    action: Optional[str] = None

    raw: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self):
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity,
            "message": self.message,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "signature": self.signature,
            "gid": self.gid,
            "sid": self.sid,
            "revision": self.revision,
            "priority": self.priority,
            "action": self.action,
        }

    @property
    def source_endpoint(self):
        if not self.src_ip:
            return "-"

        if self.src_port is None:
            return self.src_ip

        return f"{self.src_ip}:{self.src_port}"

    @property
    def destination_endpoint(self):
        if not self.dst_ip:
            return "-"

        if self.dst_port is None:
            return self.dst_ip

        return f"{self.dst_ip}:{self.dst_port}"
