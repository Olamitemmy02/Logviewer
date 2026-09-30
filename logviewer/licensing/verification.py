import base64
import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


DEFAULT_PUBLIC_KEY_PATH = (
    Path(__file__).resolve().parent / "public_key.pem"
)


class LicenseVerificationError(Exception):
    """Base exception for license verification failures."""


class LicenseFormatError(LicenseVerificationError):
    """Raised when a license has an invalid structure."""


class LicenseSignatureError(LicenseVerificationError):
    """Raised when a license signature cannot be verified."""


@dataclass(frozen=True)
class LicenseData:
    license_id: str
    customer: str
    edition: str
    issued_at: str
    expires_at: Optional[str]
    features: tuple
    metadata: Dict[str, Any]

    @property
    def expired(self) -> bool:
        if not self.expires_at:
            return False

        expiration = _parse_date(self.expires_at)
        return expiration < date.today()

    @property
    def days_remaining(self) -> Optional[int]:
        if not self.expires_at:
            return None

        expiration = _parse_date(self.expires_at)
        return (expiration - date.today()).days

    def has_feature(self, feature: str) -> bool:
        return feature in self.features


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str
    license: Optional[LicenseData] = None


def _parse_date(value: str) -> date:
    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).date()
    except ValueError:
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise LicenseFormatError(
                f"Invalid date value: {value!r}"
            ) from exc


def canonicalize_payload(payload: Dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LicenseFormatError(
            "License payload cannot be serialized."
        ) from exc


def encode_license(
    payload: Dict[str, Any],
    signature: bytes,
) -> str:
    envelope = {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii"),
    }

    encoded = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return base64.urlsafe_b64encode(encoded).decode("ascii")


def decode_license(token: str) -> Dict[str, Any]:
    if not isinstance(token, str) or not token.strip():
        raise LicenseFormatError("License token is empty.")

    try:
        raw = base64.urlsafe_b64decode(
            token.encode("ascii")
        )
        envelope = json.loads(raw.decode("utf-8"))
    except (
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise LicenseFormatError(
            "License token is not valid encoded JSON."
        ) from exc

    if not isinstance(envelope, dict):
        raise LicenseFormatError("License envelope must be an object.")

    if "payload" not in envelope or "signature" not in envelope:
        raise LicenseFormatError(
            "License envelope must contain payload and signature."
        )

    if not isinstance(envelope["payload"], dict):
        raise LicenseFormatError("License payload must be an object.")

    if not isinstance(envelope["signature"], str):
        raise LicenseFormatError("License signature must be encoded text.")

    return envelope


def load_public_key(path: Optional[Path] = None) -> Ed25519PublicKey:
    key_path = Path(path or DEFAULT_PUBLIC_KEY_PATH)

    if not key_path.is_file():
        raise LicenseVerificationError(
            f"Verification key not found: {key_path}"
        )

    try:
        key_data = key_path.read_bytes()
        return _load_public_key_bytes(key_data)
    except OSError as exc:
        raise LicenseVerificationError(
            f"Unable to read verification key: {key_path}"
        ) from exc


def _load_public_key_bytes(data: bytes) -> Ed25519PublicKey:
    from cryptography.hazmat.primitives.serialization import (
        load_pem_public_key,
    )

    try:
        key = load_pem_public_key(data)
    except ValueError as exc:
        raise LicenseVerificationError(
            "Invalid public verification key."
        ) from exc

    if not isinstance(key, Ed25519PublicKey):
        raise LicenseVerificationError(
            "Verification key is not an Ed25519 public key."
        )

    return key


def public_key_fingerprint(path: Optional[Path] = None) -> str:
    key = load_public_key(path)
    raw = key.public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )

    import hashlib

    return hashlib.sha256(raw).hexdigest()


def _build_license_data(payload: Dict[str, Any]) -> LicenseData:
    required = (
        "license_id",
        "customer",
        "edition",
        "issued_at",
        "features",
    )

    missing = [
        field
        for field in required
        if field not in payload
    ]

    if missing:
        raise LicenseFormatError(
            "License is missing required fields: "
            + ", ".join(missing)
        )

    features = payload["features"]

    if not isinstance(features, list):
        raise LicenseFormatError(
            "License features must be a list."
        )

    license_id = str(payload["license_id"]).strip()
    customer = str(payload["customer"]).strip()
    edition = str(payload["edition"]).strip().upper()
    issued_at = str(payload["issued_at"]).strip()

    if not license_id:
        raise LicenseFormatError("License ID cannot be empty.")

    if not customer:
        raise LicenseFormatError("Customer cannot be empty.")

    if not edition:
        raise LicenseFormatError("License edition cannot be empty.")

    _parse_date(issued_at)

    expires_at = payload.get("expires_at")

    if expires_at is not None:
        expires_at = str(expires_at).strip()
        _parse_date(expires_at)

    normalized_features = tuple(
        sorted(
            {
                str(feature).strip()
                for feature in features
                if str(feature).strip()
            }
        )
    )

    metadata = payload.get("metadata", {})

    if not isinstance(metadata, dict):
        raise LicenseFormatError(
            "License metadata must be an object."
        )

    return LicenseData(
        license_id=license_id,
        customer=customer,
        edition=edition,
        issued_at=issued_at,
        expires_at=expires_at,
        features=normalized_features,
        metadata=dict(metadata),
    )


def verify_license(
    token: str,
    public_key_path: Optional[Path] = None,
) -> VerificationResult:
    try:
        envelope = decode_license(token)

        payload = envelope["payload"]

        try:
            signature = base64.urlsafe_b64decode(
                envelope["signature"].encode("ascii")
            )
        except (ValueError, UnicodeDecodeError) as exc:
            raise LicenseSignatureError(
                "License signature is not valid base64."
            ) from exc

        public_key = load_public_key(public_key_path)

        try:
            public_key.verify(
                signature,
                canonicalize_payload(payload),
            )
        except InvalidSignature as exc:
            raise LicenseSignatureError(
                "License signature verification failed."
            ) from exc

        license_data = _build_license_data(payload)

        if license_data.expired:
            return VerificationResult(
                valid=False,
                reason="License has expired.",
                license=license_data,
            )

        return VerificationResult(
            valid=True,
            reason="License signature and validity checks passed.",
            license=license_data,
        )

    except LicenseVerificationError as exc:
        return VerificationResult(
            valid=False,
            reason=str(exc),
            license=None,
        )
