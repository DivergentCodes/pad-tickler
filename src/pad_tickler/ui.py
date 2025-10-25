from typing import Optional, Literal
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot


COLORS = {
    "current_byte": "bold yellow on black",
    "ciphertext": {
        "unsolved": "dark_red",
        "solved": "bright_red",
    },
    "intermediate": {
        "unsolved": "cyan",
        "solved": "turquoise2",
    },
    "plaintext": {
        "unsolved": "green",
        "solved": "spring_green2",
    },
}

type BlockType = Literal["ciphertext", "intermediate", "plaintext"]
type BlockState = Literal["unsolved", "solved", "current", "previous", "other"]


def block_to_string(block: tuple, block_type: BlockType, block_state: BlockState, current_byte_index: int = -1) -> str:
    """Convert a block to hex string and apply coloring."""
    result = ""

    normalized_block = ["??" if b is None else f"{b:02x}" for b in block]

    if block_state == "current":
        hex_bytes = []
        for i, b in enumerate(normalized_block):
            if i < current_byte_index:
                b = f"[{COLORS[block_type]['unsolved']}]{b}[/{COLORS[block_type]['unsolved']}]"
            if i > current_byte_index:
                b = f"[{COLORS[block_type]['solved']}]{b}[/{COLORS[block_type]['solved']}]"
            else:
                b = f"[{COLORS['current_byte']}]{b}[/{COLORS['current_byte']}]"
            hex_bytes.append(b)

        result = " ".join(hex_bytes)
    elif block_state == "solved":
        result = " ".join(f"[{COLORS[block_type]['solved']}]{hex_val}[/{COLORS[block_type]['solved']}]" for hex_val in normalized_block)
    elif block_state == "unsolved":
        result = " ".join(f"[{COLORS[block_type]['unsolved']}]{hex_val}[/{COLORS[block_type]['unsolved']}]" for hex_val in normalized_block)
    else:
        raise ValueError(f"Invalid block state: {block_state}")

    return result


def render(state: Optional[StateSnapshot]):
    """Render the solver state snapshot."""
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

        current_byte_index = state.byte_index_i

        # Determine highlighting and coloring based on which block is being worked on
        if block_idx == state.block_index_n - 1 and not state.complete:
            # Previous block (ciphertext prime)
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, "ciphertext",   "current", current_byte_index)
            intermediate_string     = block_to_string(intermediate_block,     "intermediate", "solved")
            plaintext_string        = block_to_string(plaintext_block,        "plaintext",    "solved")
        elif block_idx == state.block_index_n and not state.complete:
            # Current block being worked on
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, "ciphertext",   "unsolved")
            intermediate_string     = block_to_string(intermediate_block,     "intermediate", "current", current_byte_index)
            plaintext_string        = block_to_string(plaintext_block,        "plaintext",    "current", current_byte_index)
        elif block_idx < state.block_index_n and not state.complete:
            # Previous blocks
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, "ciphertext",   "solved")
            intermediate_string     = block_to_string(intermediate_block,     "intermediate", "solved")
            plaintext_string        = block_to_string(plaintext_block,        "plaintext",    "solved")
        else:
            # Other blocks after the current block being worked on
            ciphertext_prime_string = block_to_string(ciphertext_prime_block, "ciphertext",   "unsolved")
            intermediate_string     = block_to_string(intermediate_block,     "intermediate", "unsolved")
            plaintext_string        = block_to_string(plaintext_block,        "plaintext",    "unsolved")

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
            state = state_queue.get()
            if state is None:
                break
            live.update(render(state))
