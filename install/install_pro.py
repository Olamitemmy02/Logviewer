#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


PRODUCT = "LogViewer"
DISTRIBUTION = "Pro"
VERSION = "1.0.0"


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def archive_path() -> Path:
    return (
        project_root()
        / "release"
        / "dist"
        / f"{PRODUCT}-{DISTRIBUTION}-{VERSION}.tar.gz"
    )


def validate_archive(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(
            f"Pro release archive not found: {path}"
        )

    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()

    if not names:
        raise RuntimeError("Pro release archive is empty")

    if not any(
        "/logviewer/pro/" in name
        for name in names
    ):
        raise RuntimeError(
            "Invalid Pro archive: Pro package not found"
        )

    if any(
        Path(name).name
        in {
            "logviewer_private_key.pem",
            "private_key.pem",
            "license.key",
            "credentials.json",
        }
        for name in names
    ):
        raise RuntimeError(
            "Invalid Pro archive: private material detected"
        )


def extract_archive(path: Path, destination: Path) -> Path:
    with tarfile.open(path, "r:gz") as archive:
        archive.extractall(destination, filter="data")

    extracted = destination / f"{PRODUCT}-{DISTRIBUTION}-{VERSION}"

    if not extracted.is_dir():
        raise RuntimeError(
            "Pro archive has an unexpected directory layout"
        )

    return extracted


def install_package(package_root: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        str(package_root),
    ]

    completed = subprocess.run(
        command,
        check=False,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            "Pro installation failed"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install LogViewer Pro"
    )

    parser.add_argument(
        "--archive",
        type=Path,
        default=archive_path(),
        help="Path to the LogViewer Pro release archive",
    )

    args = parser.parse_args()

    try:
        validate_archive(args.archive)

        with tempfile.TemporaryDirectory(
            prefix="logviewer-pro-install-"
        ) as temporary_directory:
            package_root = extract_archive(
                args.archive,
                Path(temporary_directory),
            )

            print(
                f"Installing {PRODUCT} {DISTRIBUTION} "
                f"{VERSION}..."
            )

            install_package(package_root)

        print()
        print("LogViewer Pro installation: PASSED")
        return 0

    except Exception as exc:
        print(
            f"LogViewer Pro installation failed: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
