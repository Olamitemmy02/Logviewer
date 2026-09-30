#!/usr/bin/env python3

import argparse
import base64
import json
import secrets
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional


# Ensure this administrative tool imports the current repository
# rather than an older installed copy of LogViewer.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)

from logviewer.licensing.verification import (
    canonicalize_payload,
    verify_license,
)


DEFAULT_PRIVATE_KEY = (
    Path.home()
    / ".config"
    / "logviewer"
    / "logviewer_private_key.pem"
)

DEFAULT_OUTPUT_DIR = (
    Path.home()
    / ".config"
    / "logviewer"
    / "issued"
)


def load_private_key(path: Path):
    if not path.is_file():
        raise FileNotFoundError(
            f"Private signing key not found: {path}"
        )

    key_data = path.read_bytes()

    key = load_pem_private_key(
        key_data,
        password=None,
    )

    return key


def generate_license_id() -> str:
    return (
        "LV-"
        + datetime.now(timezone.utc).strftime("%Y%m%d")
        + "-"
        + secrets.token_hex(6).upper()
    )


def build_payload(
    customer: str,
    edition: str,
    features: list,
    expires_at: Optional[str],
    license_id: Optional[str] = None,
) -> dict:
    issued_at = datetime.now(timezone.utc).date().isoformat()

    payload = {
        "license_id": license_id or generate_license_id(),
        "customer": customer,
        "edition": edition.upper(),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "features": sorted(
            {
                feature.strip()
                for feature in features
                if feature.strip()
            }
        ),
        "metadata": {
            "product": "LogViewer",
            "license_format": 1,
            "issuer": "LogViewer Licensing",
        },
    }

    return payload


def encode_signed_license(payload: dict, private_key) -> str:
    message = canonicalize_payload(payload)

    signature = private_key.sign(message)

    envelope = {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(
            signature
        ).decode("ascii"),
    }

    raw = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return base64.urlsafe_b64encode(raw).decode("ascii")


def validate_expiration(expires_at: Optional[str]) -> None:
    if expires_at is None:
        return

    try:
        expiration = date.fromisoformat(expires_at)
    except ValueError as exc:
        raise ValueError(
            "Expiration must use YYYY-MM-DD format."
        ) from exc

    if expiration < date.today():
        raise ValueError(
            "Expiration date cannot be in the past."
        )


def write_license(
    token: str,
    output_path: Path,
) -> None:
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        token + "\n",
        encoding="utf-8",
    )

    try:
        output_path.chmod(0o600)
    except OSError:
        pass


def create_license(args) -> int:
    private_key_path = Path(
        args.private_key
    ).expanduser()

    output_path = Path(
        args.output
    ).expanduser()

    try:
        validate_expiration(args.expires)

        private_key = load_private_key(
            private_key_path
        )

        payload = build_payload(
            customer=args.customer,
            edition=args.edition,
            features=args.feature,
            expires_at=args.expires,
            license_id=args.license_id,
        )

        token = encode_signed_license(
            payload,
            private_key,
        )

        verification = verify_license(token)

        if not verification.valid:
            print(
                "ERROR: generated license failed "
                "self-verification.",
                file=sys.stderr,
            )
            print(
                verification.reason,
                file=sys.stderr,
            )
            return 1

        write_license(
            token,
            output_path,
        )

        print()
        print("LogViewer License Created")
        print("=" * 60)
        print(
            f"License ID : {payload['license_id']}"
        )
        print(
            f"Customer   : {payload['customer']}"
        )
        print(
            f"Edition    : {payload['edition']}"
        )
        print(
            f"Issued     : {payload['issued_at']}"
        )
        print(
            "Expires    : "
            f"{payload['expires_at'] or 'Never'}"
        )
        print(
            "Features   : "
            + ", ".join(payload["features"])
        )
        print(
            f"Output     : {output_path}"
        )
        print()
        print(
            "Signature verification: PASSED"
        )

        return 0

    except Exception as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 1


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Issue signed LogViewer Pro licenses."
        )
    )

    parser.add_argument(
        "--customer",
        required=True,
        help="Customer or organization name.",
    )

    parser.add_argument(
        "--edition",
        default="PRO",
        choices=("PRO",),
        help="LogViewer edition.",
    )

    parser.add_argument(
        "--feature",
        action="append",
        required=True,
        help=(
            "Pro feature to include. "
            "Repeat this option for multiple features."
        ),
    )

    parser.add_argument(
        "--expires",
        default=None,
        help=(
            "Expiration date in YYYY-MM-DD format. "
            "Omit for a perpetual license."
        ),
    )

    parser.add_argument(
        "--license-id",
        default=None,
        help="Optional custom license ID.",
    )

    parser.add_argument(
        "--private-key",
        default=str(DEFAULT_PRIVATE_KEY),
        help=(
            "Path to the private Ed25519 signing key."
        ),
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Output license file.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.output is None:
        safe_customer = "".join(
            character
            if character.isalnum()
            else "_"
            for character in args.customer
        ).strip("_")

        args.output = str(
            DEFAULT_OUTPUT_DIR
            / f"{safe_customer or 'customer'}.license"
        )

    return create_license(args)


if __name__ == "__main__":
    raise SystemExit(main())
