from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from .logger import write_log

console = Console()

def main_menu():
    write_log("system", "INFO", "Application started")
    write_log("network", "WARNING", "Unknown MAC address")
    write_log("firewall", "ERROR", "Blocked suspicious connection")


    while True:

        table = Table(
            title="LOG VIEWER MENU",
            border_style="cyan"
        )

        table.add_column(
            "Option",
            style="yellow"
        )

        table.add_column(
            "Function",
            style="green"
        )

        table.add_row(
            "1",
            "View Logs"
        )

        table.add_row(
            "2",
            "Search Logs"
        )

        table.add_row(
            "3",
            "Live Monitor"
        )

        table.add_row(
            "4",
            "Statistics"
        )

        table.add_row(
            "5",
            "Export Reports"
        )

        table.add_row(
            "6",
            "Settings"
        )
        table.add_row(
            "7",
            "Filters"
        )

        table.add_row(
            "0",
            "Exit"
        )

        console.print(table)


        choice = Prompt.ask(
            "Select option"
        )


        if choice == "0":

            console.print(
                "[yellow]Closing Log Viewer...[/yellow]"
            )

            break


        elif choice == "1":

            from .viewer import view_logs

            view_logs()


        elif choice == "2":

            from .search import search_menu
                
            search_menu()


        elif choice == "3":

            from .monitor import monitor_menu
             
            monitor_menu()   
            
        elif choice == "4":

            from .statistics import statistics_dashboard

            statistics_dashboard()

        elif choice == "5":

            from .exporter import exporter_menu

            exporter_menu()

        elif choice == "6":

            from .settings import settings_menu

            settings_menu()

        elif choice == "7":

            from .filters import filter_menu

            filter_menu()

        else:

            console.print(
                "[red]Invalid option[/red]"
            )
