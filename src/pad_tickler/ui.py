from typing import Optional
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot


def block_to_string(block: tuple) -> str:
   return " ".join([ f"{b:02x}" if b is not None else "??" for b in block ])


def render(state: Optional[StateSnapshot]):
    """Render the solver state."""
    if state is None:
        return Panel("Waiting for first update…", title="Padding Oracle", border_style="dim")

    if len(state.ciphertext) != len(state.intermediate) or len(state.ciphertext) != len(state.plaintext):
        raise ValueError("Ciphertext, intermediate, and plaintext must have the same number of blocks")

    # Create the UI table.
    ui_table = Table(title=f"Block {state.block_index_n} / {state.block_count - 1}  |  Byte {state.byte_index_i}  |  v{state.state_version}")
    ui_table.add_column("Block", justify="right")
    ui_table.add_column("Ciphertext")
    ui_table.add_column("Intermediate")
    ui_table.add_column("Plaintext")

    block_count = len(state.ciphertext)
    for block_n in range(block_count):

        # Get the blocks from the state snapshot.
        ciphertext_prime_block_n = state.ciphertext_prime[block_n]
        intermediate_block_n = state.intermediate[block_n]
        plaintext_block_n = state.plaintext[block_n]

        # Convert the blocks to displayable hex strings.
        ciphertext_prime_string_n = block_to_string(ciphertext_prime_block_n)
        intermediate_string_n = block_to_string(intermediate_block_n)
        plaintext_string_n = block_to_string(plaintext_block_n)

        # Add the blocks to the UI table.
        ui_table.add_row(str(block_n), ciphertext_prime_string_n, intermediate_string_n, plaintext_string_n)

    return ui_table

def ui_loop(state_queue: SingleSlotQueue[StateSnapshot]) -> None:
    """Loop the UI."""
    with Live(render(None), refresh_per_second=30, screen=False) as live:
        while True:
            state = state_queue.get()        # blocks; returns None when closed
            if state is None:
                break
            live.update(render(state))
