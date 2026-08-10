from .banner import startup
from .menu import main_menu


def start():
    """
    Main application controller.
    Starts the banner, system checks,
    and launches the Log Viewer dashboard.
    """

    # Start visual interface
    startup()

    # Launch interactive dashboard
    main_menu()
