from typing import Optional
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot


def block_to_string(block: tuple, highlight_byte_index: int = -1) -> str:
   """Convert a block to hex string with optional byte highlighting."""
   hex_bytes = []
   for i, b in enumerate(block):
       if b is not None:
           hex_val = f"{b:02x}"
           # Highlight the specific byte being worked on
           if i == highlight_byte_index:
               hex_val = f"[bold yellow on black]{hex_val}[/bold yellow on black]"
           hex_bytes.append(hex_val)
       else:
           if i == highlight_byte_index:
               hex_bytes.append("[bold yellow on black]??[/bold yellow on black]")
           else:
               hex_bytes.append("??")
   return " ".join(hex_bytes)


def render(state: Optional[StateSnapshot]):
    """Render the solver state."""
    if state is None:
        return Panel("Waiting for first update…", title="Padding Oracle", border_style="dim")

    if len(state.ciphertext) != len(state.intermediate) or len(state.ciphertext) != len(state.plaintext):
        raise ValueError("Ciphertext, intermediate, and plaintext must have the same number of blocks")

    # Create the UI table.
    ui_table = Table(title=f"Block {state.block_index_n} / {state.block_count - 1}  |  Byte {state.byte_index_i}  |  v{state.state_version}")
    ui_table.add_column("Block", justify="right")
    ui_table.add_column("Ciphertext Prime")
    ui_table.add_column("Intermediate")
    ui_table.add_column("Plaintext")

    block_count = len(state.ciphertext)
    for block_idx in range(block_count):

        # Get the blocks from the state snapshot.
        ciphertext_prime_block = state.ciphertext_prime[block_idx]
        intermediate_block = state.intermediate[block_idx]
        plaintext_block = state.plaintext[block_idx]

        # Determine if we should highlight the current byte being worked on
        current_byte_highlight = state.byte_index_i if block_idx == state.block_index_n else -1
        prev_block_highlight = state.byte_index_i if block_idx == state.block_index_n - 1 else -1

        # Convert the blocks to displayable hex strings.
        ciphertext_prime_string = block_to_string(ciphertext_prime_block, prev_block_highlight)
        intermediate_string = block_to_string(intermediate_block, current_byte_highlight)
        plaintext_string = block_to_string(plaintext_block, current_byte_highlight)

        # Add the blocks to the UI table.
        # Color the current row being worked on in red
        if block_idx == state.block_index_n - 1:
            ui_table.add_row(
                f"{block_idx}",
                f"[red]{ciphertext_prime_string}[/red]",
                f"{intermediate_string}",
                f"{plaintext_string}"
            )
        elif block_idx == state.block_index_n:
            ui_table.add_row(
                f"{block_idx}",
                f"{ciphertext_prime_string}",
                f"[cyan]{intermediate_string}[/cyan]",
                f"[green]{plaintext_string}[/green]"
            )
        else:
            ui_table.add_row(str(block_idx), ciphertext_prime_string, intermediate_string, plaintext_string)

    return ui_table

def ui_loop(state_queue: SingleSlotQueue[StateSnapshot]) -> None:
    """Loop the UI."""
    with Live(render(None), refresh_per_second=30, screen=False) as live:
        while True:
            state = state_queue.get()        # blocks; returns None when closed
            if state is None:
                break
            live.update(render(state))
