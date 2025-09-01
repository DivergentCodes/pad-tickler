import logging
from time import sleep

from rich.live import Live

from src.pad_tickler.ui import ui


logger = logging.getLogger("main")
logger.setLevel(logging.INFO)
logger.addHandler(ui.get_ui_log_handler())


def main():

    # Highest level UI components
    console = ui.get_console()
    layout, progress = ui.get_layout(console)

    # Tasks
    t1 = progress.add_task("Current batch", total=50)
    t2 = progress.add_task("Full dataset", total=2000)

    try:
        # Live loop
        with Live(layout, console=console, screen=True, transient=False, auto_refresh=False, refresh_per_second=8) as live:
            for i in range(2000):
                if not progress.tasks[t1].finished:
                    progress.advance(t1, 1)
                progress.advance(t2, 1)

                # Write logs normally.
                if i % 20 == 0:
                    logger.info("Processing batch %d …", i // 20)
                if i % 77 == 0:
                    logger.warning("Slow response from worker %d", i % 9)
                if i == 555:
                    logger.error("Transient error on item %d", i)

                # Re-render the bottom pane with the newest N lines.
                LOG_LINES_VISIBLE = layout["lower"].size - 2
                layout["lower"].update(ui.render_log_panel("Logs", LOG_LINES_VISIBLE))

                live.refresh()
                sleep(0.03)

    except KeyboardInterrupt:
        print("Exiting program....")

    finally:
        # Paint screen one last time on exit to preserve.
        console.clear()
        console.print(layout, height=console.size.height, crop=True)

if __name__ == "__main__":
    main()
