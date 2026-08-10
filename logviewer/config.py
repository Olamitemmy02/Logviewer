import json
from pathlib import Path


CONFIG_FILE = Path("config.json")


DEFAULT_CONFIG = {
    "log_directory": "logs",
    "export_directory": "exports",
    "theme": "cyan",
    "log_level": "INFO"
}


def load_config():

    if not CONFIG_FILE.exists():

        save_config(DEFAULT_CONFIG)

        return DEFAULT_CONFIG


    with open(
        CONFIG_FILE,
        "r"
    ) as file:

        return json.load(file)



def save_config(config):

    with open(
        CONFIG_FILE,
        "w"
    ) as file:

        json.dump(
            config,
            file,
            indent=4
        )
