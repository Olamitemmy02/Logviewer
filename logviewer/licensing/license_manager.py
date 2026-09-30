import os
from pathlib import Path
from typing import Optional

from .verification import (
    LicenseData,
    VerificationResult,
    verify_license,
)


APP_NAME = "logviewer"

DEFAULT_LICENSE_PATH = (
    Path.home()
    / ".config"
    / APP_NAME
    / "license.key"
)


class LicenseManager:
    """
    Manage the locally activated LogViewer license.

    The manager deliberately keeps license storage separate from
    the application source tree. The Core application therefore
    remains usable even when no Pro license is installed.
    """

    def __init__(
        self,
        license_path: Optional[Path] = None,
        public_key_path: Optional[Path] = None,
    ):
        self.license_path = Path(
            license_path or DEFAULT_LICENSE_PATH
        )
        self.public_key_path = public_key_path

    def is_activated(self) -> bool:
        return self.get_verification().valid

    def get_verification(self) -> VerificationResult:
        token = self._read_token()

        if not token:
            return VerificationResult(
                valid=False,
                reason="No LogViewer license is installed.",
                license=None,
            )

        return verify_license(
            token,
            public_key_path=self.public_key_path,
        )

    def get_license(self) -> Optional[LicenseData]:
        result = self.get_verification()

        if not result.valid:
            return None

        return result.license

    def install(self, token: str) -> VerificationResult:
        """
        Validate a license before storing it.

        Invalid licenses are never written to disk.
        """
        result = verify_license(
            token,
            public_key_path=self.public_key_path,
        )

        if not result.valid:
            return result

        self.license_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path = self.license_path.with_suffix(
            self.license_path.suffix + ".tmp"
        )

        temporary_path.write_text(
            token.strip() + "\n",
            encoding="utf-8",
        )

        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass

        temporary_path.replace(self.license_path)

        try:
            os.chmod(self.license_path, 0o600)
        except OSError:
            pass

        return result

    def remove(self) -> bool:
        try:
            self.license_path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    def status(self) -> dict:
        result = self.get_verification()

        data = result.license

        return {
            "valid": result.valid,
            "reason": result.reason,
            "license_id": data.license_id if data else None,
            "customer": data.customer if data else None,
            "edition": data.edition if data else None,
            "issued_at": data.issued_at if data else None,
            "expires_at": data.expires_at if data else None,
            "days_remaining": (
                data.days_remaining
                if data
                else None
            ),
            "features": (
                list(data.features)
                if data
                else []
            ),
            "license_path": str(self.license_path),
        }

    def _read_token(self) -> Optional[str]:
        try:
            if not self.license_path.is_file():
                return None

            token = self.license_path.read_text(
                encoding="utf-8"
            ).strip()

            return token or None

        except (OSError, UnicodeDecodeError):
            return None
