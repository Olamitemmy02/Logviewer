from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from .config import load_config, save_config


console = Console()



def show_settings(config):

    table = Table(
        title="Current Settings",
        border_style="cyan"
    )


    table.add_column(
        "Setting",
        style="yellow"
    )

    table.add_column(
        "Value",
        style="green"
    )


    for key, value in config.items():

        table.add_row(
            key,
            value
        )


    console.print(table)



def settings_menu():

    config = load_config()


    while True:

        show_settings(config)


        table = Table(
            title="Settings Menu",
            border_style="cyan"
        )


        table.add_column(
            "Option"
        )

        table.add_column(
            "Action"
        )


        table.add_row(
            "1",
            "Change Log Directory"
        )

        table.add_row(
            "2",
            "Change Export Directory"
        )

        table.add_row(
            "3",
            "Change Theme"
        )

        table.add_row(
            "4",
            "Change Log Level"
        )

        table.add_row(
            "0",
            "Save and Exit"
        )


        console.print(table)


        choice = Prompt.ask(
            "Select option"
        )


        if choice == "1":

            config["log_directory"] = Prompt.ask(
                "New log directory"
            )


        elif choice == "2":

            config["export_directory"] = Prompt.ask(
                "New export directory"
            )


        elif choice == "3":

            config["theme"] = Prompt.ask(
                "New theme color"
            )


        elif choice == "4":

            config["log_level"] = Prompt.ask(
                "New log level"
            )


        elif choice == "0":

            save_config(config)

            console.print(
                "[green]Settings saved[/green]"
            )

            break


        else:

            console.print(
                "[red]Invalid option[/red]"
            )
