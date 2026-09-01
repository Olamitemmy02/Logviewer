import json
import logging
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"


def load_config():
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "log_directory": "logs",
            "log_level": "INFO"
        }


def get_log_directory():
    config = load_config()

    directory = config.get("log_directory", "logs")
    path = Path(directory)

    if not path.is_absolute():
        path = BASE_DIR.parent / path

    path.mkdir(parents=True, exist_ok=True)

    return path


LOG_FILE = get_log_directory() / "logviewer.log"


def get_logger():
    config = load_config()

    level_name = config.get(
        "log_level",
        "INFO"
    ).upper()

    level = getattr(
        logging,
        level_name,
        logging.INFO
    )

    app_logger = logging.getLogger("LogViewer")

    app_logger.setLevel(level)

    if not app_logger.handlers:

        handler = logging.FileHandler(
            LOG_FILE,
            encoding="utf-8"
        )

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )

        handler.setFormatter(formatter)
        app_logger.addHandler(handler)

    return app_logger


logger = get_logger()


def write_log(category, level, message):

    formatted_message = (
        f"[{category}] {message}"
    )

    method = getattr(
        logger,
        str(level).lower(),
        logger.info
    )

    method(formatted_message)


def info(message, category="system"):
    write_log(category, "INFO", message)


def warning(message, category="system"):
    write_log(category, "WARNING", message)


def error(message, category="system"):
    write_log(category, "ERROR", message)


def debug(message, category="system"):
    write_log(category, "DEBUG", message)
