from typing import Optional
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

from pad_tickler.event_queue import SingleSlotQueue
from pad_tickler.event_snapshot import SolverState


# ---- Rendering ----
def render(state: Optional[SolverState]):
    """Render the solver state."""
    if state is None:
        return Panel("Waiting for first update…", title="Padding Oracle", border_style="dim")

    t = Table(title=f"Block {state.block_index_n}  |  Byte {state.byte_index_i}  |  v{state.event_version}")
    t.add_column("Idx", justify="right")
    t.add_column("Plaintext (hex)")
    for idx, block in enumerate(state.plaintext_n):
        hexrow = block.hex() if block else ""
        # highlight the current byte in the current block (optional)
        if idx == state.block_index_n and 0 <= state.byte_index_i < state.block_size and block:
            b = bytearray(block)
            # mark byte with brackets for visibility
            hexbytes = [f"{b[i]:02x}" for i in range(len(b))]
            hexbytes[state.byte_index_i] = f"[{hexbytes[state.byte_index_i]}]"
            hexrow = " ".join(hexbytes)
        else:
            hexrow = " ".join(block.hex()[i:i+2] for i in range(0, len(block)*2, 2))
        t.add_row(str(idx), hexrow)
    return t

def ui_loop(state_queue: SingleSlotQueue[SolverState]) -> None:
    """Loop the UI."""
    with Live(render(None), refresh_per_second=30, screen=False) as live:
        while True:
            state = state_queue.get()        # blocks; returns None when closed
            if state is None:
                break
            live.update(render(state))
