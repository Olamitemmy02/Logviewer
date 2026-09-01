import os
import platform
import socket
import shutil


def get_system_info():
    """
    Collect basic information about the system
    running LogViewer.
    """

    return {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "distribution": _get_distribution(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "user": os.getenv("USER") or os.getenv("USERNAME"),
        "journalctl": shutil.which("journalctl") is not None,
        "rsyslog": _service_exists("rsyslog"),
    }


def _get_distribution():
    """
    Get Linux distribution information.
    """

    try:
        if os.path.exists("/etc/os-release"):
            data = {}

            with open(
                "/etc/os-release",
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                for line in file:
                    if "=" not in line:
                        continue

                    key, value = line.strip().split("=", 1)

                    data[key] = value.strip('"')

            return data.get(
                "PRETTY_NAME",
                data.get("NAME", "Unknown")
            )

    except OSError:
        pass

    return platform.system()


def _service_exists(service):
    """
    Check whether a service appears to exist.
    """

    systemctl = shutil.which("systemctl")

    if not systemctl:
        return False

    result = os.system(
        f"{systemctl} cat {service}.service "
        "> /dev/null 2>&1"
    )

    return result == 0
