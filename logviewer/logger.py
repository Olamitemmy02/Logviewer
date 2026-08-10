from pathlib import Path
from datetime import datetime


LOG_DIR = Path("logs")

LOG_DIR.mkdir(exist_ok=True)



def write_log(category, level, message):
    """
    Write logs into separate category files.

    Example:
    write_log(
        "system",
        "INFO",
        "Application started"
    )
    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    log_file = LOG_DIR / f"{category}.log"


    entry = (
        f"{timestamp} "
        f"{level.upper()} "
        f"{message}\n"
    )


    with open(
        log_file,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(entry)

