import gzip

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


from .registry import ParserRegistry


@dataclass
class SourceInfo:
    path: Path
    name: str
    source_type: str
    status: str
    parser: Optional[str] = None
    description: Optional[str] = None
    size: int = 0
    readable: bool = False

    # Parser coverage metrics
    total_lines: int = 0
    parsed_lines: int = 0
    unparsed_lines: int = 0
    parse_coverage: float = 0.0

    @property
    def is_analyzable(self) -> bool:
        return self.status in {
            "SUPPORTED",
            "PARTIAL",
            "ROTATED",
        } and self.parser is not None


class SourceClassifier:
    """
    Classifies discovered log sources according to:

        - file type
        - readability
        - backup/rotated state
        - parser availability
        - parser coverage

    Parsers may use either:

        1. line-oriented coverage through parse_line()
        2. structured coverage through measure_coverage()

    This allows transaction/block-oriented formats such as APT
    to define meaningful coverage without weakening the normal
    line-parser model.
    """

    BACKUP_SUFFIXES = {
        ".backup",
        ".bak",
        ".old",
        ".orig",
        ".save",
    }

    ROTATED_SUFFIX_PATTERN = r"^\.\d+$"

    FULL_SUPPORT_THRESHOLD = 100.0

    def __init__(
        self,
        registry: Optional[ParserRegistry] = None,
    ):
        self.registry = registry or ParserRegistry()

    def classify(self, path) -> SourceInfo:
        path = Path(path)

        if path.is_dir():
            return SourceInfo(
                path=path,
                name=path.name,
                source_type="directory",
                status="DIRECTORY",
                readable=self._is_readable(path),
            )

        if not path.exists():
            return SourceInfo(
                path=path,
                name=path.name,
                source_type="missing",
                status="UNSUPPORTED",
                readable=False,
            )

        if not self._is_readable(path):
            return SourceInfo(
                path=path,
                name=path.name,
                source_type="file",
                status="UNREADABLE",
                size=self._safe_size(path),
                readable=False,
            )

        if self._is_backup(path):
            return SourceInfo(
                path=path,
                name=path.name,
                source_type="backup",
                status="BACKUP",
                size=self._safe_size(path),
                readable=True,
            )

        size = self._safe_size(path)
        rotated = self._is_rotated(path)

        if size == 0:
            return SourceInfo(
                path=path,
                name=path.name,
                source_type="rotated" if rotated else "file",
                status="EMPTY",
                size=0,
                readable=True,
            )

        parser_path = (
            self._logical_parser_path(path)
            if rotated
            else path
        )

        parser = self.registry.get_parser(parser_path)

        if parser is None:
            return SourceInfo(
                path=path,
                name=path.name,
                source_type="rotated" if rotated else "file",
                status="ROTATED" if rotated else "UNSUPPORTED",
                size=size,
                readable=True,
            )

        (
            total_lines,
            parsed_lines,
            unparsed_lines,
            parser_errors,
        ) = self._measure_parser_coverage(
            path,
            parser,
            parser_path,
        )

        coverage = self._calculate_coverage(
            total_lines,
            parsed_lines,
        )

        if rotated:
            status = "ROTATED"
        else:
            status = self._determine_status(
                total_lines=total_lines,
                parsed_lines=parsed_lines,
                coverage=coverage,
                parser_errors=parser_errors,
            )

        return SourceInfo(
            path=path,
            name=path.name,
            source_type="rotated" if rotated else "file",
            status=status,
            parser=parser.name,
            description=parser.description,
            size=size,
            readable=True,
            total_lines=total_lines,
            parsed_lines=parsed_lines,
            unparsed_lines=unparsed_lines,
            parse_coverage=coverage,
        )

    def classify_many(self, paths):
        return [
            self.classify(path)
            for path in paths
        ]

    def _measure_parser_coverage(
        self,
        path,
        parser,
        parser_path,
    ):
        """
        Measure parser coverage.

        Structured parsers may expose:

            measure_coverage(path)

        Line-oriented parsers continue to use parse_line().
        """

        structured_measurement = getattr(
            parser,
            "measure_coverage",
            None,
        )

        if callable(structured_measurement):
            try:
                return structured_measurement(path)
            except (
                OSError,
                PermissionError,
                EOFError,
            ):
                return 0, 0, 0, 0
            except Exception:
                return 0, 0, 0, 1

        return self._measure_line_parser_coverage(
            path,
            parser,
            parser_path,
        )

    def _measure_line_parser_coverage(
        self,
        path,
        parser,
        parser_path,
    ):
        """
        Measure coverage for traditional line-oriented parsers.
        """

        total_lines = 0
        parsed_lines = 0
        unparsed_lines = 0
        parser_errors = 0

        try:
            with self._open_text(path) as handle:

                for line in handle:
                    if not line.strip():
                        continue

                    total_lines += 1

                    try:
                        event = parser.parse_line(
                            line,
                            parser_path,
                        )
                    except Exception:
                        parser_errors += 1
                        unparsed_lines += 1
                        continue

                    if event is None:
                        unparsed_lines += 1
                        continue

                    parse_status = getattr(
                        event,
                        "parse_status",
                        "unparsed",
                    )

                    if parse_status == "parsed":
                        parsed_lines += 1
                    else:
                        unparsed_lines += 1

        except (
            OSError,
            PermissionError,
            EOFError,
        ):
            return 0, 0, 0, 0

        return (
            total_lines,
            parsed_lines,
            unparsed_lines,
            parser_errors,
        )

    @staticmethod
    def _calculate_coverage(
        total_lines,
        parsed_lines,
    ) -> float:

        if total_lines <= 0:
            return 0.0

        return round(
            (parsed_lines / total_lines) * 100,
            2,
        )

    def _determine_status(
        self,
        total_lines,
        parsed_lines,
        coverage,
        parser_errors,
    ):
        if total_lines == 0:
            return "EMPTY"

        if parsed_lines == 0:
            return "UNSUPPORTED"

        if coverage >= self.FULL_SUPPORT_THRESHOLD:
            return "SUPPORTED"

        return "PARTIAL"

    @staticmethod
    def _is_readable(path: Path) -> bool:
        try:
            with SourceClassifier._open_text(path):
                return True
        except (
            OSError,
            PermissionError,
            EOFError,
        ):
            return False

    @staticmethod
    def _safe_size(path: Path) -> int:
        try:
            return path.stat().st_size
        except (
            OSError,
            PermissionError,
        ):
            return 0

    @classmethod
    def _is_backup(cls, path: Path) -> bool:
        name = path.name.lower()

        if any(
            name.endswith(suffix)
            for suffix in cls.BACKUP_SUFFIXES
        ):
            return True

        return any(
            marker in name
            for marker in (
                ".backup.",
                ".bak.",
                ".old.",
                ".save.",
            )
        )

    @staticmethod
    def _is_rotated(path: Path) -> bool:
        name = path.name.lower()

        if name.endswith(".gz"):
            name = name[:-3]

        parts = name.split(".")

        if len(parts) < 2:
            return False

        return parts[-1].isdigit()

    @staticmethod
    def _logical_parser_path(path: Path) -> Path:
        """
        Convert a rotated filename into its active-log filename.

        Examples:

            error.log.1
                -> error.log

            error.log.2.gz
                -> error.log

            access.log.5.gz
                -> access.log
        """

        name = path.name

        if name.lower().endswith(".gz"):
            name = name[:-3]

        parts = name.split(".")

        if len(parts) >= 2 and parts[-1].isdigit():
            name = ".".join(parts[:-1])

        return path.with_name(name)

    @staticmethod
    def _open_text(path: Path):
        """
        Open plain-text and gzip-compressed logs uniformly.
        """

        if path.name.lower().endswith(".gz"):
            return gzip.open(
                path,
                "rt",
                encoding="utf-8",
                errors="replace",
            )

        return path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        )
