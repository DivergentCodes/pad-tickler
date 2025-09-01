import logging
from collections import deque

from rich.align import Align
from rich.panel import Panel
from rich.table import Table

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


def gen_blocks_table():
    t = Table(show_header=True, show_lines=False, show_edge=False, padding=(0,0))
    t.add_column("Block (n)", justify="center", style="dim", width=10, no_wrap=True, overflow="crop")
    t.add_column("Ciphertext (Cₙ)", justify="center", style="blue", width=49, no_wrap=True, overflow="crop")
    t.add_column("Intermediate (Iₙ)", justify="center", style="yellow", width=49, no_wrap=True, overflow="crop")
    t.add_column("Plaintext (Pₙ)", justify="center", style="green", width=49, no_wrap=True, overflow="crop")
    t.add_row("IV", "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??", "", "")
    t.add_row("00000000", *["?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??"]*3)
    t.add_row("00000001", *["?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??"]*3)
    t = Align(t, align="center")
    return Panel(t, title="Blocks", padding=(1,1))


def phase_table(title, rows):
    t = Table(padding=(0,2), show_header=False, show_lines=False, show_edge=False)
    t.add_column("Block", style="cyan", width=12, no_wrap=True, overflow="crop")
    t.add_column("Var",   style="cyan", width=6,  no_wrap=True, overflow="crop")
    t.add_column("Bytes", style="green", width=48, no_wrap=True, overflow="crop")
    for r in rows: t.add_row(*r)
    t = Align(t, align="center")
    return Panel(t, title=title, padding=(1,1))
