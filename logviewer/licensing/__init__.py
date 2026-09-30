from .console import LicenseConsole
from .feature_gate import (
    FeatureAccessError,
    FeatureGate,
    requires_feature,
)
from .license_manager import LicenseManager
from .verification import (
    LicenseData,
    LicenseFormatError,
    LicenseSignatureError,
    LicenseVerificationError,
    VerificationResult,
    canonicalize_payload,
    decode_license,
    encode_license,
    public_key_fingerprint,
    verify_license,
)

__all__ = [
    "LicenseConsole",
    "FeatureAccessError",
    "FeatureGate",
    "LicenseData",
    "LicenseFormatError",
    "LicenseManager",
    "LicenseSignatureError",
    "LicenseVerificationError",
    "VerificationResult",
    "canonicalize_payload",
    "decode_license",
    "encode_license",
    "public_key_fingerprint",
    "requires_feature",
    "verify_license",
]
