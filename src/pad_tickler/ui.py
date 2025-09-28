from typing import Optional
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot


def block_to_string(block: tuple, highlight_byte_index: int = -1, block_color: str = "") -> str:
   """Convert a block to hex string with optional byte highlighting and block coloring."""
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

   result = " ".join(hex_bytes)

   # Apply block-level color if specified
   if block_color:
       result = f"[{block_color}]{result}[/{block_color}]"

   return result


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

        # Determine highlighting and coloring based on which block is being worked on
        if block_idx == state.block_index_n - 1 and not state.complete:
            # Previous block (ciphertext prime) - red with byte highlighting
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, state.byte_index_i, "red")
            intermediate_string = block_to_string(intermediate_block)
            plaintext_string = block_to_string(plaintext_block)
        elif block_idx == state.block_index_n and not state.complete:
            # Current block being worked on - intermediate in cyan, plaintext in green, both with byte highlighting
            ciphertext_prime_string = block_to_string(ciphertext_prime_block)
            intermediate_string = block_to_string(intermediate_block, state.byte_index_i, "cyan")
            plaintext_string = block_to_string(plaintext_block, state.byte_index_i, "green")
        else:
            # Other blocks - no special coloring or highlighting
            ciphertext_prime_string = block_to_string(ciphertext_prime_block)
            intermediate_string = block_to_string(intermediate_block)
            plaintext_string = block_to_string(plaintext_block)

        # Add the blocks to the UI table.
        block_idx_string = str(block_idx)
        if block_idx == 0:
            block_idx_string = "IV"
            intermediate_string = ""
            plaintext_string = ""
        ui_table.add_row(block_idx_string, ciphertext_prime_string, intermediate_string, plaintext_string)

    return ui_table

def ui_loop(state_queue: SingleSlotQueue[StateSnapshot]) -> None:
    """Loop the UI."""
    with Live(render(None), refresh_per_second=30, screen=False) as live:
        while True:
            state = state_queue.get()        # blocks; returns None when closed
            if state is None:
                break
            live.update(render(state))
