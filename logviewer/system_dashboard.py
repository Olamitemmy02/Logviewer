from .discovery import get_log_summary
from .system import get_system_info


def show_system_dashboard():
    print()
    print("=" * 60)
    print("                 LOGVIEWER")
    print("              SYSTEM DASHBOARD")
    print("=" * 60)

    info = get_system_info()

    print(f"Hostname       : {info['hostname']}")
    print(f"OS             : {info['distribution']}")
    print(f"Kernel         : {info['kernel']}")
    print(f"Architecture   : {info['architecture']}")
    print(f"Python         : {info['python']}")

    print()
    print("LOGGING SERVICES")
    print("-" * 60)

    print(
        f"journalctl     : "
        f"{'Available' if info['journalctl'] else 'Not available'}"
    )

    print(
        f"rsyslog        : "
        f"{'Detected' if info['rsyslog'] else 'Not detected'}"
    )

    print()
    print("DISCOVERED LOG FILES")
    print("-" * 60)

    logs = get_log_summary()

    if not logs:
        print("No accessible log files were discovered.")
        return

    for index, log in enumerate(logs, start=1):

        size = log["size"]

        if size >= 1024 * 1024:
            size_text = f"{size / (1024 * 1024):.2f} MB"

        elif size >= 1024:
            size_text = f"{size / 1024:.2f} KB"

        else:
            size_text = f"{size} B"

        print(
            f"[{index:02}] "
            f"{log['path']} "
            f"({size_text})"
        )

    print()
    print(f"Total accessible logs: {len(logs)}")
