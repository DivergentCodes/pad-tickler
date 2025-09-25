from typing import Optional
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot


def render(state: Optional[StateSnapshot]):
    """Render the solver state."""
    if state is None:
        return Panel("Waiting for first update…", title="Padding Oracle", border_style="dim")

    if len(state.ciphertext_n) != len(state.intermediate_n) or len(state.ciphertext_n) != len(state.plaintext_n):
        raise ValueError("Ciphertext, intermediate, and plaintext must have the same number of blocks")

    # Create the UI table.
    ui_table = Table(title=f"Block {state.block_index_n} / {state.block_count - 1}  |  Byte {state.byte_index_i}  |  v{state.state_version}")
    ui_table.add_column("Idx", justify="right")
    ui_table.add_column("Ciphertext (hex)")
    ui_table.add_column("Intermediate (hex)")
    ui_table.add_column("Plaintext (hex)")

    block_count = len(state.ciphertext_n)
    placeholder_block = " ".join(["??"] * state.block_size * 2)
    for idx in range(block_count):

        # Get the blocks from the state snapshot.
        cn_block = state.ciphertext_n[idx]
        intermediate_block = state.intermediate_n[idx]
        plaintext_block = state.plaintext_n[idx]

        # Convert the blocks to displayable hex strings.
        cn_hex = cn_block.hex(" ") if cn_block else placeholder_block
        intermediate_hex = intermediate_block.hex(" ") if intermediate_block else placeholder_block
        plaintext_hex = plaintext_block.hex(" ") if plaintext_block else placeholder_block

        # Add the blocks to the UI table.
        ui_table.add_row(str(idx), cn_hex, intermediate_hex, plaintext_hex)

    return ui_table

def ui_loop(state_queue: SingleSlotQueue[StateSnapshot]) -> None:
    """Loop the UI."""
    with Live(render(None), refresh_per_second=30, screen=False) as live:
        while True:
            state = state_queue.get()        # blocks; returns None when closed
            if state is None:
                break
            live.update(render(state))
