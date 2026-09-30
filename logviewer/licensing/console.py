from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm, Prompt

from .feature_gate import FeatureAccessError
from .license_manager import LicenseManager


class LicenseConsole:
    """Interactive LogViewer license management workflow."""

    def __init__(
        self,
        manager: Optional[LicenseManager] = None,
        console: Optional[Console] = None,
    ) -> None:
        self.manager = manager or LicenseManager()
        self.console = console or Console()

    def activate(self) -> bool:
        """Prompt for and install a license token from a file."""

        self.console.print(
            Panel(
                "Activate a LogViewer Pro license.\n\n"
                "Select the license file supplied by the "
                "LogViewer licensing issuer.",
                title="Activate Pro License",
                border_style="cyan",
            )
        )

        path_text = Prompt.ask(
            "License file path",
        ).strip()

        if not path_text:
            self.console.print(
                "[yellow]Activation cancelled.[/yellow]"
            )
            return False

        license_path = Path(path_text).expanduser()

        if not license_path.is_file():
            self.console.print(
                Panel(
                    f"[red]License file was not found:[/red]\n"
                    f"{license_path}",
                    title="Activation Failed",
                    border_style="red",
                )
            )
            return False

        try:
            token = license_path.read_text(
                encoding="utf-8"
            ).strip()
        except (OSError, UnicodeDecodeError) as exc:
            self.console.print(
                Panel(
                    f"[red]Unable to read the license file.[/red]\n\n"
                    f"{exc}",
                    title="Activation Failed",
                    border_style="red",
                )
            )
            return False

        if not token:
            self.console.print(
                Panel(
                    "[red]The license file is empty.[/red]",
                    title="Activation Failed",
                    border_style="red",
                )
            )
            return False

        result = self.manager.install(token)

        if not result.valid or result.license is None:
            self.console.print(
                Panel(
                    "[red]The license could not be activated.[/red]\n\n"
                    f"Reason: {result.reason}\n\n"
                    "The invalid license was not installed.",
                    title="Activation Failed",
                    border_style="red",
                )
            )
            return False

        self.console.print(
            Panel(
                "[green]LogViewer Pro license activated successfully.[/green]\n\n"
                f"License ID: {result.license.license_id}\n"
                f"Customer: {result.license.customer}\n"
                f"Edition: {result.license.edition}\n"
                f"Expires: {result.license.expires_at or 'Never'}\n"
                f"Features: {len(result.license.features)}",
                title="Activation Successful",
                border_style="green",
            )
        )

        return True

    def show_status(self) -> dict:
        """Display the current license status."""

        status = self.manager.status()

        if not status["valid"]:
            self.console.print(
                Panel(
                    "[yellow]LogViewer is running without an active "
                    "valid Pro license.[/yellow]\n\n"
                    f"Reason: {status['reason']}",
                    title="License Status",
                    border_style="yellow",
                )
            )
            return status

        table = Table(
            title="LogViewer Pro License",
            show_header=True,
        )

        table.add_column("Property")
        table.add_column("Value")

        table.add_row(
            "Status",
            "[green]ACTIVE[/green]",
        )
        table.add_row(
            "License ID",
            str(status["license_id"]),
        )
        table.add_row(
            "Customer",
            str(status["customer"]),
        )
        table.add_row(
            "Edition",
            str(status["edition"]),
        )
        table.add_row(
            "Issued",
            str(status["issued_at"]),
        )
        table.add_row(
            "Expires",
            str(status["expires_at"] or "Never"),
        )

        days_remaining = status["days_remaining"]

        if days_remaining is None:
            remaining_text = "Perpetual"
        elif days_remaining < 0:
            remaining_text = "Expired"
        else:
            remaining_text = f"{days_remaining} day(s)"

        table.add_row(
            "Time Remaining",
            remaining_text,
        )
        table.add_row(
            "Installed At",
            str(status["license_path"]),
        )

        self.console.print(table)

        self.console.print()

        feature_table = Table(
            title="Licensed Pro Features",
            show_header=True,
        )
        feature_table.add_column("#")
        feature_table.add_column("Feature")

        for index, feature in enumerate(
            status["features"],
            start=1,
        ):
            feature_table.add_row(
                str(index),
                feature,
            )

        if status["features"]:
            self.console.print(feature_table)
        else:
            self.console.print(
                "[yellow]No Pro features are licensed.[/yellow]"
            )

        return status

    def deactivate(self) -> bool:
        """Remove the currently installed local license."""

        status = self.manager.status()

        if not status["valid"] and not self.manager.license_path.is_file():
            self.console.print(
                "[yellow]No installed license was found.[/yellow]"
            )
            return False

        confirmed = Confirm.ask(
            "Remove the installed LogViewer license?",
            default=False,
        )

        if not confirmed:
            self.console.print(
                "[yellow]Deactivation cancelled.[/yellow]"
            )
            return False

        removed = self.manager.remove()

        if removed:
            self.console.print(
                Panel(
                    "[green]The local LogViewer license has been "
                    "deactivated.[/green]\n\n"
                    "Core functionality remains available. "
                    "Pro features will require another valid license.",
                    title="License Deactivated",
                    border_style="green",
                )
            )
            return True

        self.console.print(
            Panel(
                "[yellow]No license was removed.[/yellow]",
                title="Deactivation",
                border_style="yellow",
            )
        )
        return False

    def menu(self) -> None:
        """Run the interactive license-management menu."""

        while True:
            self.console.print()
            self.console.print(
                Panel(
                    "[bold]1.[/bold] Activate Pro License\n"
                    "[bold]2.[/bold] License Status\n"
                    "[bold]3.[/bold] Deactivate License\n"
                    "[bold]0.[/bold] Back",
                    title="LogViewer License Management",
                    border_style="cyan",
                )
            )

            choice = Prompt.ask(
                "Select an option",
                choices=["1", "2", "3", "0"],
                default="0",
            )

            if choice == "1":
                self.activate()
                Prompt.ask(
                    "Press Enter to continue",
                    default="",
                )
            elif choice == "2":
                self.show_status()
                Prompt.ask(
                    "Press Enter to continue",
                    default="",
                )
            elif choice == "3":
                self.deactivate()
                Prompt.ask(
                    "Press Enter to continue",
                    default="",
                )
            elif choice == "0":
                return


__all__ = ["LicenseConsole"]
