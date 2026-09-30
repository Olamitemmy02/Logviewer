import json
from pathlib import Path
from typing import Any, Dict


CONFIG_FILE = Path("config.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "log_directory": "/var/log",
    "export_directory": "exports",
    "theme": "cyan",
    "log_level": "INFO",
}


def _write_config(config: Dict[str, Any]) -> None:
    """
    Write configuration safely to disk.
    """
    CONFIG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with CONFIG_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            config,
            file,
            indent=4,
        )


def save_config(config: Dict[str, Any]) -> None:
    """
    Save LogViewer configuration.
    """
    _write_config(config)


def load_config() -> Dict[str, Any]:
    """
    Load LogViewer configuration.

    Missing or invalid configuration files fall back
    to the default configuration.
    """
    if not CONFIG_FILE.exists():
        config = DEFAULT_CONFIG.copy()
        save_config(config)
        return config

    try:
        with CONFIG_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            loaded = json.load(file)

    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
    ):
        config = DEFAULT_CONFIG.copy()
        save_config(config)
        return config

    if not isinstance(loaded, dict):
        config = DEFAULT_CONFIG.copy()
        save_config(config)
        return config

    config = DEFAULT_CONFIG.copy()
    config.update(loaded)

    return config


def get_log_directory() -> Path:
    """
    Return the configured log directory.
    """
    config = load_config()

    value = config.get(
        "log_directory",
        DEFAULT_CONFIG["log_directory"],
    )

    return Path(str(value)).expanduser()


def get_export_directory() -> Path:
    """
    Return the configured export directory.
    """
    config = load_config()

    value = config.get(
        "export_directory",
        DEFAULT_CONFIG["export_directory"],
    )

    return Path(str(value)).expanduser()


def get_theme() -> str:
    """
    Return the configured Rich theme color.
    """
    config = load_config()

    return str(
        config.get(
            "theme",
            DEFAULT_CONFIG["theme"],
        )
    )


def get_log_level() -> str:
    """
    Return the configured logging level.
    """
    config = load_config()

    return str(
        config.get(
            "log_level",
            DEFAULT_CONFIG["log_level"],
        )
    ).upper()
