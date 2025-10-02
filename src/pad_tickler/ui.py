from typing import Optional, Literal
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot


current_byte_color = "bold yellow on black"
ciphertext_unsolved_color = "dark_red"
ciphertext_solved_color = "bright_red"
intermediate_unsolved_color = "cyan"
intermediate_solved_color = "turquoise2"
plaintext_unsolved_color = "green"
plaintext_solved_color = "spring_green2"

type BlockState = Literal["unsolved", "solved", "current", "previous", "other"]


def block_to_string(block: tuple, block_state: BlockState, unsolved_color: str, solved_color: str, current_byte_index: int = -1) -> str:
    """Convert a block to hex string and apply coloring."""
    result = ""

    normalized_block = ["??" if b is None else f"{b:02x}" for b in block]

    if block_state == "current":
        hex_bytes = []
        for i, b in enumerate(normalized_block):
            if i < current_byte_index:
                b = f"[{unsolved_color}]{b}[/{unsolved_color}]"
            if i > current_byte_index:
                b = f"[{solved_color}]{b}[/{solved_color}]"
            else:
                b = f"[{current_byte_color}]{b}[/{current_byte_color}]"
            hex_bytes.append(b)

        result = " ".join(hex_bytes)
    elif block_state == "solved":
        result = " ".join(f"[{solved_color}]{hex_val}[/{solved_color}]" for hex_val in normalized_block)
    elif block_state == "unsolved":
        result = " ".join(f"[{unsolved_color}]{hex_val}[/{unsolved_color}]" for hex_val in normalized_block)
    else:
        raise ValueError(f"Invalid block state: {block_state}")

    return result


def render(state: Optional[StateSnapshot]):
    """Render the solver state."""
    if state is None:
        return Panel("Waiting for first update…", title="Padding Oracle", border_style="dim")

    if len(state.ciphertext) != len(state.intermediate) or len(state.ciphertext) != len(state.plaintext):
        raise ValueError("Ciphertext, intermediate, and plaintext must have the same number of blocks")

    # Create the UI table.
    ui_table = Table(title=f"Block {state.block_index_n} / {state.block_count}  |  Byte {state.byte_index_i + 1}  |  v{state.state_version}")
    ui_table.add_column("Block", justify="right")
    ui_table.add_column("Ciphertext Prime Cₙ₋₁′")
    ui_table.add_column("Intermediate Iₙ")
    ui_table.add_column("Plaintext Pₙ")

    block_count = len(state.ciphertext)
    for block_idx in range(block_count):

        # Get the blocks from the state snapshot.
        ciphertext_prime_block = state.ciphertext_prime[block_idx]
        intermediate_block = state.intermediate[block_idx]
        plaintext_block = state.plaintext[block_idx]

        # Determine highlighting and coloring based on which block is being worked on
        if block_idx == state.block_index_n - 1 and not state.complete:
            # Previous block (ciphertext prime) - red with byte highlighting
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, "current", ciphertext_unsolved_color, ciphertext_solved_color, state.byte_index_i)
            intermediate_string = block_to_string(intermediate_block, "solved", intermediate_unsolved_color, intermediate_solved_color)
            plaintext_string = block_to_string(plaintext_block, "solved", plaintext_unsolved_color, plaintext_solved_color)
        elif block_idx == state.block_index_n and not state.complete:
            # Current block being worked on - intermediate in cyan, plaintext in green, both with byte highlighting
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, "unsolved", ciphertext_unsolved_color, ciphertext_solved_color)
            intermediate_string = block_to_string(intermediate_block, "current", intermediate_unsolved_color, intermediate_solved_color, state.byte_index_i)
            plaintext_string = block_to_string(plaintext_block, "current", plaintext_unsolved_color, plaintext_solved_color, state.byte_index_i)
        elif block_idx < state.block_index_n and not state.complete:
            # Previous blocks - intermediate in cyan, plaintext in green, both with byte highlighting
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, "solved", ciphertext_unsolved_color, ciphertext_solved_color)
            intermediate_string = block_to_string(intermediate_block, "solved", intermediate_unsolved_color, intermediate_solved_color)
            plaintext_string = block_to_string(plaintext_block, "solved", plaintext_unsolved_color, plaintext_solved_color)
        else:
            # Other blocks after the current block being worked on
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, "unsolved", ciphertext_unsolved_color, ciphertext_solved_color)
            intermediate_string = block_to_string(intermediate_block, "unsolved", intermediate_unsolved_color, intermediate_solved_color)
            plaintext_string = block_to_string(plaintext_block, "unsolved", plaintext_unsolved_color, plaintext_solved_color)

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
