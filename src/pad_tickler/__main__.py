import logging
from time import sleep

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn

from src.pad_tickler.ui import ui


logger = logging.getLogger("main")
logger.setLevel(logging.INFO)

console = ui.get_console()


# Data for the run
blocks_panel = ui.gen_blocks_table()
phase1_panel = ui.phase_table("Phase 1: discover intermediate block", [
    ("Ciphertext",   "Cₙ₋₁′", "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"),
    ("Padding",      "k = 2", "                                          02 02"),
    ("Intermediate", "Iₙ",    "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? d5 1f"),
])
phase2_panel = ui.phase_table("Phase 2: recover plaintext block", [
    ("Intermediate", "Iₙ",    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"),
    ("Ciphertext",   "Cₙ₋₁′", "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"),
    ("Plaintext",    "Pₙ",    "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??"),
])

# Progress status
progress = ui.get_progress(console)
t1 = progress.add_task("Current batch", total=50)
t2 = progress.add_task("Full dataset", total=2000)
progress_panel = Panel(progress, title="Processing", padding=(1,1))

# Layout
layout = Layout()
layout.split_column(
    Layout(name="upper", size=12),
    Layout(name="middle", size=16),
    Layout(name="lower", size=14),
)
layout["upper"].update(blocks_panel)
layout["middle"].split_row(Layout(name="left", ratio=1), Layout(name="right", ratio=1))
layout["left"].split_column(Layout(name="p1", size=8), Layout(name="p2", size=8))
layout["p1"].update(phase1_panel)
layout["p2"].update(phase2_panel)
layout["right"].update(progress_panel)

LOG_LINES_VISIBLE = 10
layout["lower"].update(ui.render_log_panel("Logs", LOG_LINES_VISIBLE))

def main():

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
