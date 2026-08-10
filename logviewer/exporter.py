from pathlib import Path
from datetime import datetime
import json
import csv

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt


console = Console()


LOG_DIRECTORY = Path("logs")
EXPORT_DIRECTORY = Path("exports")


EXPORT_DIRECTORY.mkdir(exist_ok=True)



def collect_logs():

    logs = []

    if not LOG_DIRECTORY.exists():
        return logs


    for file in LOG_DIRECTORY.glob("*.log"):

        with open(
            file,
            "r",
            errors="ignore"
        ) as log:

            logs.append(
                {
                    "file": file.name,
                    "entries": log.readlines()
                }
            )


    return logs



def export_txt(data):

    filename = (
        EXPORT_DIRECTORY /
        f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )


    with open(
        filename,
        "w"
    ) as report:


        for log in data:

            report.write(
                f"\n===== {log['file']} =====\n"
            )

            for entry in log["entries"]:

                report.write(entry)


    return filename



def export_json(data):

    filename = (
        EXPORT_DIRECTORY /
        f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )


    with open(
        filename,
        "w"
    ) as report:

        json.dump(
            data,
            report,
            indent=4
        )


    return filename



def export_csv(data):

    filename = (
        EXPORT_DIRECTORY /
        f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )


    with open(
        filename,
        "w",
        newline=""
    ) as report:


        writer = csv.writer(report)


        writer.writerow(
            [
                "Log File",
                "Entry"
            ]
        )


        for log in data:

            for entry in log["entries"]:

                writer.writerow(
                    [
                        log["file"],
                        entry.strip()
                    ]
                )


    return filename



def exporter_menu():

    data = collect_logs()


    if not data:

        console.print(
            "[red]No logs available[/red]"
        )

        return



    table = Table(
        title="Export Manager",
        border_style="cyan"
    )


    table.add_column(
        "Option",
        style="yellow"
    )


    table.add_column(
        "Format",
        style="green"
    )


    table.add_row(
        "1",
        "TXT Report"
    )


    table.add_row(
        "2",
        "JSON Report"
    )


    table.add_row(
        "3",
        "CSV Report"
    )


    table.add_row(
        "0",
        "Back"
    )


    console.print(table)


    choice = Prompt.ask(
        "Select export type"
    )


    if choice == "1":

        file = export_txt(data)


    elif choice == "2":

        file = export_json(data)


    elif choice == "3":

        file = export_csv(data)


    else:

        return


    console.print(
        f"[green]Export created:[/green] {file}"
    )
