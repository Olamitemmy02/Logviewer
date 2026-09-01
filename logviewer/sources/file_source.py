from pathlib import Path
from typing import Iterator


class FileLogSource:
    """
    Reads events directly from a system log file.
    """

    def __init__(self, path):
        self.path = Path(path)

    def exists(self):
        return self.path.exists()

    def is_file(self):
        return self.path.is_file()

    def is_readable(self):
        try:
            with self.path.open(
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:
                file.read(1)

            return True

        except (PermissionError, OSError):
            return False

    def read_lines(self) -> Iterator[str]:
        """
        Yield lines from the log file.
        """

        if not self.exists():
            raise FileNotFoundError(
                f"Log file does not exist: {self.path}"
            )

        if not self.is_file():
            raise ValueError(
                f"Not a regular file: {self.path}"
            )

        if not self.is_readable():
            raise PermissionError(
                f"Permission denied: {self.path}"
            )

        with self.path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line in file:
                line = line.rstrip("\n")

                if line:
                    yield line

    def read_last(self, lines=100):
        """
        Read the last N lines of the file.
        """

        if lines <= 0:
            return []

        content = []

        for line in self.read_lines():
            content.append(line)

            if len(content) > lines:
                content.pop(0)

        return content
