from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import PurePosixPath
from typing import Any, Dict


class InvestigationEvidencePackageVerifier:
    """Verify the integrity of a LogViewer evidence package."""

    SUPPORTED_ALGORITHM = "SHA-256"
    REQUIRED_FILES = {"report.md", "report.json"}

    def verify(self, package_path: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "verified": False,
            "status": "checking",
            "package": str(package_path),
            "algorithm": self.SUPPORTED_ALGORITHM,
            "investigation": {},
            "files": [],
            "errors": [],
            "warnings": [],
            "limitations": [
                "Successful verification confirms that checked archive artifacts match the hashes recorded in the package manifest.",
                "Verification does not prove authenticity of the package or manifest.",
                "Verification does not prove that the underlying evidence or analysis is correct.",
                "Verification is not a legal chain-of-custody procedure.",
            ],
        }

        try:
            with zipfile.ZipFile(str(package_path), "r") as archive:
                self._verify_archive(archive, result)

        except FileNotFoundError:
            result["status"] = "error"
            result["errors"].append(
                f"Evidence package not found: {package_path}"
            )

        except zipfile.BadZipFile:
            result["status"] = "error"
            result["errors"].append(
                "The supplied file is not a valid ZIP evidence package."
            )

        except OSError as exc:
            result["status"] = "error"
            result["errors"].append(
                f"Unable to read evidence package: {exc}"
            )

        except Exception as exc:
            result["status"] = "error"
            result["errors"].append(
                f"Unexpected verification error: {exc}"
            )

        if result["status"] != "error":
            result["verified"] = not result["errors"]
            result["status"] = (
                "verified"
                if result["verified"]
                else "failed"
            )

        return result

    def _verify_archive(
        self,
        archive: zipfile.ZipFile,
        result: Dict[str, Any],
    ) -> None:
        manifest_name = self._find_manifest(archive)

        if manifest_name is None:
            result["status"] = "failed"
            result["errors"].append(
                "No unique manifest.json was found in the evidence package."
            )
            return

        try:
            raw_manifest = archive.read(manifest_name)
            manifest = json.loads(raw_manifest.decode("utf-8"))

        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            result["status"] = "failed"
            result["errors"].append(
                f"Unable to parse manifest.json: {exc}"
            )
            return

        if not isinstance(manifest, dict):
            result["status"] = "failed"
            result["errors"].append(
                "The evidence package manifest must contain a JSON object."
            )
            return

        self._read_investigation_metadata(manifest, result)
        self._verify_manifest_structure(archive, manifest, result)

    def _read_investigation_metadata(
        self,
        manifest: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        investigation = manifest.get("investigation")

        if not isinstance(investigation, dict):
            result["status"] = "failed"
            result["errors"].append(
                "Manifest field 'investigation' must be an object."
            )
            return

        result["investigation"] = {
            "id": investigation.get("investigation_id"),
            "title": investigation.get("title"),
        }

    def _verify_manifest_structure(
        self,
        archive: zipfile.ZipFile,
        manifest: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        integrity = manifest.get("integrity")

        if not isinstance(integrity, dict):
            result["status"] = "failed"
            result["errors"].append(
                "Manifest field 'integrity' must be an object."
            )
            return

        algorithm = integrity.get("algorithm")

        if algorithm != self.SUPPORTED_ALGORITHM:
            result["status"] = "failed"
            result["errors"].append(
                "Unsupported integrity algorithm: "
                f"{algorithm!r}. "
                f"Expected {self.SUPPORTED_ALGORITHM!r}."
            )
            return

        manifest_files = manifest.get("files")

        if not isinstance(manifest_files, list):
            result["status"] = "failed"
            result["errors"].append(
                "Manifest field 'files' must be a list."
            )
            return

        entries: Dict[str, Dict[str, Any]] = {}

        for entry in manifest_files:
            if not isinstance(entry, dict):
                result["status"] = "failed"
                result["errors"].append(
                    "Every manifest file entry must be an object."
                )
                continue

            path = entry.get("path")

            if not isinstance(path, str) or not path:
                result["status"] = "failed"
                result["errors"].append(
                    "Manifest file entries must contain a non-empty path."
                )
                continue

            if path in entries:
                result["status"] = "failed"
                result["errors"].append(
                    f"Duplicate manifest file entry: {path}"
                )
                continue

            entries[path] = entry

        self._verify_required_files(entries, result)

        for entry in entries.values():
            self._verify_file_entry(
                archive,
                entry,
                result,
            )

    def _verify_required_files(
        self,
        entries: Dict[str, Dict[str, Any]],
        result: Dict[str, Any],
    ) -> None:
        found_required = set()

        for path in entries:
            filename = PurePosixPath(path).name

            if filename in self.REQUIRED_FILES:
                found_required.add(filename)

        missing = self.REQUIRED_FILES - found_required

        for filename in sorted(missing):
            result["status"] = "failed"
            result["errors"].append(
                "Required report artifact is missing from the manifest: "
                f"{filename}"
            )

    def _verify_file_entry(
        self,
        archive: zipfile.ZipFile,
        entry: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        archive_path = entry.get("path")

        if not isinstance(archive_path, str):
            return

        file_result = {
            "path": archive_path,
            "format": entry.get("format"),
            "expected_size": entry.get("size"),
            "actual_size": None,
            "expected_sha256": entry.get("sha256"),
            "actual_sha256": None,
            "verified": False,
        }

        result["files"].append(file_result)

        if not self._is_safe_archive_path(archive_path):
            result["status"] = "failed"
            result["errors"].append(
                f"Unsafe archive path in manifest: {archive_path}"
            )
            return

        expected_hash = entry.get("sha256")

        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(
                character not in "0123456789abcdefABCDEF"
                for character in expected_hash
            )
        ):
            result["status"] = "failed"
            result["errors"].append(
                f"Invalid SHA-256 hash in manifest for {archive_path}."
            )
            return

        try:
            data = archive.read(archive_path)

        except KeyError:
            result["status"] = "failed"
            result["errors"].append(
                "Manifest references a file that is missing from "
                f"the archive: {archive_path}"
            )
            return

        actual_size = len(data)
        actual_hash = hashlib.sha256(data).hexdigest()

        file_result["actual_size"] = actual_size
        file_result["actual_sha256"] = actual_hash

        expected_size = entry.get("size")

        if expected_size != actual_size:
            result["status"] = "failed"
            result["errors"].append(
                f"Size mismatch for {archive_path}: "
                f"expected {expected_size}, actual {actual_size}."
            )

        if expected_hash.lower() != actual_hash.lower():
            result["status"] = "failed"
            result["errors"].append(
                f"SHA-256 mismatch for {archive_path}: "
                f"expected {expected_hash}, actual {actual_hash}."
            )

        if (
            expected_size == actual_size
            and expected_hash.lower() == actual_hash.lower()
        ):
            file_result["verified"] = True

    @staticmethod
    def _find_manifest(
        archive: zipfile.ZipFile,
    ) -> str | None:
        manifests = [
            name
            for name in archive.namelist()
            if PurePosixPath(name).name == "manifest.json"
        ]

        if len(manifests) != 1:
            return None

        return manifests[0]

    @staticmethod
    def _is_safe_archive_path(path: str) -> bool:
        pure_path = PurePosixPath(path)

        if pure_path.is_absolute():
            return False

        if ".." in pure_path.parts:
            return False

        return True


__all__ = ["InvestigationEvidencePackageVerifier"]
