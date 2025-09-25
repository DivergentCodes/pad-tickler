import logging
from collections import deque
from typing import List, Tuple

from rich.align import Align
from rich.layout import Layout
from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pad_tickler.models.cipher_block import CipherBlockSet

LOG_BUFFER = deque(maxlen=5000)
LEVEL_STYLE = {
    logging.DEBUG: "dim",
    logging.INFO: "",
    logging.WARNING: "yellow",
    logging.ERROR: "red",
    logging.CRITICAL: "bold red",
}

class UILogHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        LOG_BUFFER.append((record.levelno, msg))

logger = logging.getLogger("ui")
logger.setLevel(logging.INFO)

uih = UILogHandler()
uih.setFormatter(logging.Formatter("%(asctime)s  %(levelname)s  %(message)s", "%H:%M:%S"))
logger.addHandler(uih)


def get_ui_log_handler():
    uih = UILogHandler()
    uih.setFormatter(logging.Formatter("%(asctime)s  %(levelname)s  %(message)s", "%H:%M:%S"))
    return uih


def get_console():
    ORIGINAL_HEIGHT = Console().size.height
    console = Console(height=ORIGINAL_HEIGHT - 4)
    return console


def render_log_panel(title: str, max_lines: int) -> Panel:
    """Render exactly max_lines log entries (cropped to width, no wrap)."""
    # take the last max_lines entries; pad with blanks if fewer
    items = list(LOG_BUFFER)[-max_lines:]
    if len(items) < max_lines:
        items = [("", "")] * (max_lines - len(items)) + items

    # single-column grid avoids wrapping; crops long lines horizontally
    grid = Table.grid(padding=(0, 0))
    grid.add_column(no_wrap=True, overflow="crop")  # fills available width
    for lvl, msg in items:
        style = LEVEL_STYLE.get(lvl, "")
        grid.add_row(f"[{style}]{msg}[/{style}]" if style else msg)
    return Panel(grid, title=title, padding=(0,1))


def gen_blocks_table(iv_block: CipherBlockSet, ciphertext_blocks: CipherBlockSet) -> Panel:
    default_block_string = "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??"

    # Table & headers
    t = Table(show_header=True, show_lines=False, show_edge=False, padding=(0,0))
    t.add_column("Block (n)", justify="center", style="dim", width=10, no_wrap=True, overflow="crop")
    t.add_column("Ciphertext (Cₙ)", justify="center", style="blue", width=49, no_wrap=True, overflow="crop")
    t.add_column("Intermediate (Iₙ)", justify="center", style="yellow", width=49, no_wrap=True, overflow="crop")
    t.add_column("Plaintext (Pₙ)", justify="center", style="green", width=49, no_wrap=True, overflow="crop")

    # IV
    if not iv_block:
        iv_string = default_block_string
    else:
        iv_string = " ".join([f"{b:02x}" for b in iv_block.current_block()])
    t.add_row("IV", iv_string, "", "")

    if ciphertext_blocks:
        for i, block in enumerate(ciphertext_blocks.blocks):
            block_string = " ".join([f"{b:02x}" for b in block])
            t.add_row(f"{i:08x}", block_string, "", "")

    t = Align(t, align="center")
    return Panel(t, title="Blocks", padding=(1,1))


def phase_table(title, rows) -> Panel:
    t = Table(padding=(0,2), show_header=False, show_lines=False, show_edge=False)
    t.add_column("Block", style="cyan", width=12, no_wrap=True, overflow="crop")
    t.add_column("Var",   style="cyan", width=6,  no_wrap=True, overflow="crop")
    t.add_column("Bytes", style="green", width=48, no_wrap=True, overflow="crop")
    for r in rows: t.add_row(*r)
    t = Align(t, align="center")
    return Panel(t, title=title, padding=(1,1))


def brute_force_table(title, rows) -> Panel:
    t = Table(padding=(0,2), show_header=False, show_lines=False, show_edge=False)
    t.add_column("Block", style="cyan", width=12, no_wrap=True, overflow="crop")
    t.add_column("Var",   style="cyan", width=6,  no_wrap=True, overflow="crop")
    t.add_column("Bytes", style="green", width=48, no_wrap=True, overflow="crop")
    for r in rows: t.add_row(*r)
    t = Align(t, align="center")
    return Panel(t, title=title, padding=(1,1))


def get_progress(console: Console) -> Tuple[Panel, Progress]:
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("{task.completed}/{task.total}"),
        expand=True,
        console=console,
    )
    progress_panel = Panel(progress, title="Processing", padding=(1,1))
    return progress_panel, progress

def get_layout(console: Console) -> Tuple[Layout, Progress]:
    # Data for the run
    blocks_panel = gen_blocks_table(CipherBlockSet([]), CipherBlockSet([]))
    phase1_panel = phase_table("Phase 1: discover intermediate block", [
        ("Ciphertext",   "Cₙ₋₁′", "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"),
        ("Padding",      "k = 2", "                                          02 02"),
        ("Intermediate", "Iₙ",    "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? d5 1f"),
    ])
    phase2_panel = phase_table("Phase 2: recover plaintext block", [
        ("Intermediate", "Iₙ",    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"),
        ("Ciphertext",   "Cₙ₋₁′", "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"),
        ("Plaintext",    "Pₙ",    "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??"),
    ])

    # Progress status
    progress_panel, progress = get_progress(console)

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
    layout["lower"].update(render_log_panel("Logs", LOG_LINES_VISIBLE))
    return layout, progress


def update_log_panel(layout: Layout, log_lines_visible: int):
    """Update the log panel with the newest N lines."""
    layout["lower"].update(render_log_panel("Logs", log_lines_visible))