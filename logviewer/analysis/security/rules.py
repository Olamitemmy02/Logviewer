"""
Core security classification rules.

This module classifies normalized LogViewer events into
security-relevant activity categories.

Design principles:
    - Prefer explicit security semantics over generic metadata.
    - Do not treat running as root as privilege escalation.
    - Do not treat automated root services as privilege activity.
    - Preserve real administrative activity such as sudo and su.
    - Avoid generic systemd lifecycle false positives.
    - Keep rule matching deterministic and explainable.
"""

from logviewer.events import Event


# ============================================================================
# AUTHENTICATION
# ============================================================================

AUTH_FAILURE_PATTERNS = (
    "failed password",
    "authentication failure",
    "authentication failed",
    "failed authentication",
    "invalid user",
    "login failed",
    "failed login",
    "maximum authentication attempts",
    "max auth attempts",
)

AUTH_SUCCESS_PATTERNS = (
    "accepted password",
    "accepted publickey",
    "accepted keyboard-interactive",
    "authentication successful",
    "authentication succeeded",
    "login successful",
)

SESSION_PATTERNS = (
    "session opened",
    "session closed",
)

INTERACTIVE_AUTH_EVENT_TYPES = {
    "authentication",
    "login",
    "ssh_authentication",
}

AUTOMATED_SESSION_TYPES = {
    "cron.service",
    "systemd-user",
}

AUTOMATED_SESSION_PREFIXES = (
    "user@",
)


# ============================================================================
# PRIVILEGE
# ============================================================================

"""
Privilege activity is intentionally based on explicit privilege-management
mechanisms.

We do NOT treat these as privilege activity by themselves:

    uid=0
    euid=0
    user=root
    session opened for user root
    session closed for user root
    cron running as root
    systemd running as root

Those describe execution context, not necessarily a privilege transition.
"""

PRIVILEGE_PATTERNS = (
    "sudo:",
    "sudo[",
    "su:",
    "su[",
    "pkexec",
    "doas",
    "privilege escalation",
    "privilege elevated",
    "privilege dropped",
    "switching to root",
    "switched to root",
)

PRIVILEGE_PROCESSES = {
    "sudo",
    "su",
    "pkexec",
    "doas",
}

PRIVILEGE_COMMANDS = {
    "sudo",
    "su",
    "pkexec",
    "doas",
}


# ============================================================================
# COMMAND / EXECUTION
# ============================================================================

EXECUTION_EVENT_TYPES = {
    "process",
    "process_start",
    "process_exec",
    "command",
    "command_execution",
    "exec",
    "execution",
}

EXECUTION_MESSAGE_PATTERNS = (
    "executed command",
    "command executed",
    "process started",
    "process spawned",
    "execve(",
    "exec:",
)

NON_EXECUTION_EVENT_TYPES = {
    "service_started",
    "service_stopped",
    "service_start",
    "service_stop",
    "socket_started",
    "socket_stopped",
}


# ============================================================================
# NETWORK
# ============================================================================

NETWORK_EVENT_TYPES = {
    "network",
    "connection",
    "network_connection",
    "socket",
    "firewall",
    "packet",
    "dns",
    "http",
    "https",
    "ssh",
}

NETWORK_MESSAGE_PATTERNS = (
    "connection from",
    "connection accepted",
    "connection refused",
    "connection reset",
    "connect to",
    "connected to",
    "incoming connection",
    "outgoing connection",
    "src=",
    "dst=",
    "source=",
    "destination=",
)


# ============================================================================
# FILE ACTIVITY
# ============================================================================

FILE_EVENT_TYPES = {
    "file",
    "file_access",
    "file_create",
    "file_modify",
    "file_delete",
    "file_change",
}

FILE_MESSAGE_PATTERNS = (
    "opened file",
    "created file",
    "modified file",
    "deleted file",
    "file access",
    "file changed",
)


# ============================================================================
# SENSITIVE RESOURCES
# ============================================================================

SENSITIVE_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/ssh/",
    "/root/.ssh/",
    "/home/",
    "/var/log/auth.log",
    "/var/log/secure",
)


# ============================================================================
# SECURITY CONTROLS
# ============================================================================

SECURITY_CONTROL_PATTERNS = (
    "ufw",
    "iptables",
    "nftables",
    "nft ",
    "firewalld",
    "apparmor",
    "selinux",
    "auditd",
    "crowdsec",
    "snort",
)


# ============================================================================
# PARSING / DATA QUALITY
# ============================================================================

def is_parsing_fallback(event: Event) -> bool:
    """
    Return True when the parser could not normalize the event.
    """

    return (
        (event.parse_status or "").strip().lower()
        == "fallback"
    )


def is_partial_parse(event: Event) -> bool:
    """
    Return True when only part of the event was normalized.
    """

    return (
        (event.parse_status or "").strip().lower()
        == "partial"
    )


# ============================================================================
# GENERIC HELPERS
# ============================================================================

def _message(event: Event) -> str:
    return (event.message or "").strip().lower()


def _process(event: Event) -> str:
    return (event.process or "").strip().lower()


def _command(event: Event) -> str:
    return (event.command or "").strip().lower()


def _event_type(event: Event) -> str:
    return (event.event_type or "").strip().lower()


def _first_command_token(command: str) -> str:
    """
    Extract the executable name from a command.

    Examples:

        sudo su
            -> sudo

        /usr/bin/sudo -l
            -> sudo

        /bin/su -
            -> su
    """

    if not command:
        return ""

    token = command.split(maxsplit=1)[0]

    return token.rsplit("/", 1)[-1]


def _is_automated_session(event: Event) -> bool:
    """
    Identify service-managed sessions that should not be treated as
    interactive authentication activity.
    """

    event_type = _event_type(event)

    if event_type in AUTOMATED_SESSION_TYPES:
        return True

    return any(
        event_type.startswith(prefix)
        for prefix in AUTOMATED_SESSION_PREFIXES
    )


def _has_network_fields(event: Event) -> bool:
    """
    Determine whether the normalized event contains actual network data.
    """

    return any(
        (
            event.src_ip,
            event.src_port is not None,
            event.dst_ip,
            event.dst_port is not None,
            event.domain,
            event.url,
            event.protocol,
        )
    )


def _has_execution_fields(event: Event) -> bool:
    """
    Determine whether an event contains explicit execution semantics.

    Generic process/PID/command fields are deliberately NOT sufficient
    because systemd journal entries commonly contain daemon metadata.
    """

    event_type = _event_type(event)
    message = _message(event)

    if event_type in EXECUTION_EVENT_TYPES:
        return True

    if any(
        pattern in message
        for pattern in EXECUTION_MESSAGE_PATTERNS
    ):
        return True

    return False


# ============================================================================
# AUTHENTICATION CLASSIFICATION
# ============================================================================

def is_auth_activity(event: Event) -> bool:
    """
    Detect meaningful authentication or user-session activity.

    Automated cron and systemd-user sessions are excluded.
    """

    message = _message(event)
    event_type = _event_type(event)

    # Explicit successful authentication.
    if any(
        pattern in message
        for pattern in AUTH_SUCCESS_PATTERNS
    ):
        return True

    # Explicit authentication event types.
    if event_type in INTERACTIVE_AUTH_EVENT_TYPES:
        return True

    # Explicit authentication failure.
    if any(
        pattern in message
        for pattern in AUTH_FAILURE_PATTERNS
    ):
        return True

    # Session activity.
    if any(
        pattern in message
        for pattern in SESSION_PATTERNS
    ):
        if _is_automated_session(event):
            return False

        return True

    return False


# ============================================================================
# PRIVILEGE CLASSIFICATION
# ============================================================================

def is_privilege_activity(event: Event) -> bool:
    """
    Detect explicit privilege-management activity.

    A root execution context alone is NOT considered privilege activity.

    Examples that SHOULD match:

        sudo su
        sudo nft list ruleset
        sudo ufw status verbose
        su
        pkexec ...
        doas ...
        pam_unix(sudo:session)...
        pam_unix(su:session)...

    Examples that should NOT match:

        cron running as root
        systemd running as root
        session opened for user root
        session closed for user root
        uid=0
        euid=0
    """

    process = _process(event)
    command = _command(event)
    message = _message(event)

    # Explicit privilege-management process.
    if process in PRIVILEGE_PROCESSES:
        return True

    # Explicit privilege-management command.
    first_token = _first_command_token(command)

    if first_token in PRIVILEGE_COMMANDS:
        return True

    # Explicit privilege-management message.
    if any(
        pattern in message
        for pattern in PRIVILEGE_PATTERNS
    ):
        return True

    return False


# ============================================================================
# COMMAND / EXECUTION CLASSIFICATION
# ============================================================================

def is_command_activity(event: Event) -> bool:
    """
    Detect explicit command/process execution activity.

    Systemd service lifecycle events and automated service sessions
    are excluded from this rule.
    """

    event_type = _event_type(event)

    if event_type in NON_EXECUTION_EVENT_TYPES:
        return False

    if _is_automated_session(event):
        return False

    return _has_execution_fields(event)


# ============================================================================
# NETWORK CLASSIFICATION
# ============================================================================

def is_network_activity(event: Event) -> bool:
    """
    Detect meaningful network activity.

    Actual network fields are preferred over generic systemd socket
    lifecycle messages.
    """

    event_type = _event_type(event)
    message = _message(event)

    if _has_network_fields(event):
        return True

    if event_type in NETWORK_EVENT_TYPES:
        return True

    if any(
        pattern in message
        for pattern in NETWORK_MESSAGE_PATTERNS
    ):
        return True

    return False


# ============================================================================
# FILE CLASSIFICATION
# ============================================================================

def is_file_activity(event: Event) -> bool:
    """
    Detect file operations or explicit file-change activity.
    """

    event_type = _event_type(event)
    message = _message(event)

    if event_type in FILE_EVENT_TYPES:
        return True

    if event.file_path:
        return True

    return any(
        pattern in message
        for pattern in FILE_MESSAGE_PATTERNS
    )


# ============================================================================
# SENSITIVE RESOURCE CLASSIFICATION
# ============================================================================

def is_sensitive_path(event: Event) -> bool:
    """
    Detect references to security-sensitive filesystem locations.
    """

    values = (
        event.file_path,
        event.message,
        event.command,
        event.url,
    )

    for value in values:
        if not value:
            continue

        text = str(value).lower()

        if any(
            path in text
            for path in SENSITIVE_PATHS
        ):
            return True

    return False


# ============================================================================
# SECURITY CONTROL CLASSIFICATION
# ============================================================================

def is_security_control_activity(event: Event) -> bool:
    """
    Detect observable activity involving security controls.

    This describes the observed activity; it does not imply maliciousness.
    """

    values = (
        event.message,
        event.command,
        event.process,
        event.file_path,
    )

    for value in values:
        if not value:
            continue

        text = str(value).lower()

        if any(
            pattern in text
            for pattern in SECURITY_CONTROL_PATTERNS
        ):
            return True

    return False


# ============================================================================
# RULE DISPATCH
# ============================================================================

def matching_rule_ids(event: Event) -> list[str]:
    """
    Return every security rule that matches an event.

    Rules are evaluated independently because one event may legitimately
    contain multiple types of security-relevant evidence.

    Example:

        sudo nft list ruleset

    may produce:

        PRIVILEGE_ACTIVITY
        SECURITY_CONTROL

    depending on the normalized event fields.
    """

    matches: list[str] = []

    message = _message(event)

    # Authentication activity.
    if is_auth_activity(event):
        matches.append("AUTH_ACTIVITY")

        # Authentication failure is a more specific observation.
        if any(
            pattern in message
            for pattern in AUTH_FAILURE_PATTERNS
        ):
            matches.append("AUTH_FAILURE")

    # Privilege activity.
    if is_privilege_activity(event):
        matches.append("PRIVILEGE_ACTIVITY")

    # Command/process execution.
    if is_command_activity(event):
        matches.append("COMMAND_ACTIVITY")

    # Network activity.
    if is_network_activity(event):
        matches.append("NETWORK_ACTIVITY")

    # File activity.
    if is_file_activity(event):
        matches.append("FILE_ACTIVITY")

    # Sensitive filesystem references.
    if is_sensitive_path(event):
        matches.append("SENSITIVE_PATH")

    # Security-control activity.
    if is_security_control_activity(event):
        matches.append("SECURITY_CONTROL")

    # Parser/data-quality observations.
    if is_parsing_fallback(event):
        matches.append("PARSING_FALLBACK")

    if is_partial_parse(event):
        matches.append("PARTIAL_PARSE")

    return matches
