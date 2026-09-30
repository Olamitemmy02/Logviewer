from functools import wraps
from typing import Callable, Optional

from .license_manager import LicenseManager


class FeatureAccessError(RuntimeError):
    """Raised when a paid feature is unavailable."""


class FeatureGate:
    """
    Runtime access controller for LogViewer Pro features.

    Core code never needs to depend on Pro. Pro components can
    create a FeatureGate and require individual capabilities.
    """

    def __init__(
        self,
        license_manager: Optional[LicenseManager] = None,
    ):
        self.license_manager = (
            license_manager or LicenseManager()
        )

    def check(self, feature: str) -> bool:
        license_data = self.license_manager.get_license()

        if license_data is None:
            return False

        return license_data.has_feature(feature)

    def require(self, feature: str) -> None:
        result = self.license_manager.get_verification()

        if not result.valid or result.license is None:
            raise FeatureAccessError(
                "This LogViewer Pro feature requires a valid "
                "Pro license."
            )

        if not result.license.has_feature(feature):
            raise FeatureAccessError(
                f"The installed license does not include "
                f"the '{feature}' feature."
            )


def requires_feature(
    feature: str,
    gate: Optional[FeatureGate] = None,
) -> Callable:
    """
    Decorator for Pro-only functions.

    Example:

        @requires_feature("correlation")
        def run_pro_correlation():
            ...
    """
    active_gate = gate or FeatureGate()

    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            active_gate.require(feature)
            return function(*args, **kwargs)

        return wrapper

    return decorator
