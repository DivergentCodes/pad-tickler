# ui_min.py
from __future__ import annotations
import time, threading, random
from dataclasses import dataclass, field
from typing import Optional, Tuple, Generic, TypeVar

import click
from rich.live import Live
from rich.table import Table
from rich.panel import Panel

# ---- Minimal immutable snapshot (adapt to your SolverState) ----
@dataclass(frozen=True, slots=True)
class SolverState:
    version: int
    block_index: int
    byte_index: int
    block_size: int = 16
    plaintext_n: Tuple[bytes, ...] = field(default_factory=tuple)  # tuple of 16-byte blocks

# ---- Size-1, latest-only queue (single consumer) ----
T = TypeVar("T")

class SingleSlotQueue(Generic[T]):
    """Thread-safe, size=1, latest-wins queue. One consumer reads the newest item."""
    def __init__(self) -> None:
        self._cv = threading.Condition()
        self._has_value = False
        self._value: Optional[T] = None
        self._closed = False

    def publish(self, item: T) -> None:
        with self._cv:
            self._value = item       # overwrite any stale value
            self._has_value = True
            self._cv.notify()        # wake exactly one waiting consumer

    def close(self) -> None:
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    def get(self, timeout: Optional[float] = None) -> Optional[T]:
        """Blocks until a value is available or the queue is closed. Returns None on close."""
        with self._cv:
            ok = self._cv.wait_for(lambda: self._has_value or self._closed, timeout)
            if not ok:
                raise TimeoutError("queue get() timed out")
            if self._closed and not self._has_value:
                return None
            v = self._value
            self._value = None
            self._has_value = False
            return v

# ---- Rendering ----
def render(state: Optional[SolverState]):
    if state is None:
        return Panel("Waiting for first update…", title="Padding Oracle", border_style="dim")

    t = Table(title=f"Block {state.block_index}  |  Byte {state.byte_index}  |  v{state.version}")
    t.add_column("Idx", justify="right")
    t.add_column("Plaintext (hex)")
    for idx, block in enumerate(state.plaintext_n):
        hexrow = block.hex() if block else ""
        # highlight the current byte in the current block (optional)
        if idx == state.block_index and 0 <= state.byte_index < state.block_size and block:
            b = bytearray(block)
            # mark byte with brackets for visibility
            hexbytes = [f"{b[i]:02x}" for i in range(len(b))]
            hexbytes[state.byte_index] = f"[{hexbytes[state.byte_index]}]"
            hexrow = " ".join(hexbytes)
        else:
            hexrow = " ".join(block.hex()[i:i+2] for i in range(0, len(block)*2, 2))
        t.add_row(str(idx), hexrow)
    return t

def ui_loop(ch: SingleSlotQueue[SolverState]) -> None:
    with Live(render(None), refresh_per_second=30, screen=False) as live:
        while True:
            state = ch.get()        # blocks; returns None when closed
            if state is None:
                break
            live.update(render(state))

# ---- Demo producer (replace with your real algorithm) ----
def demo_producer(ch: SingleSlotQueue[SolverState], blocks: int = 3, block_size: int = 16):
    plaintext = [bytearray(block_size) for _ in range(blocks)]
    version = 0
    for bi in range(blocks):
        for byte_i in range(block_size - 1, -1, -1):
            # simulate discovery
            time.sleep(0.03)  # ~33 FPS max
            plaintext[bi][byte_i] = random.randint(32, 126)
            version += 1
            snap = SolverState(
                version=version,
                block_index=bi,
                byte_index=byte_i,
                block_size=block_size,
                plaintext_n=tuple(bytes(b) for b in plaintext),
            )
            ch.publish(snap)
    ch.close()

@click.command()
def run():
    """Minimal Rich/Click UI that renders latest SolverState snapshots."""
    ch: SingleSlotQueue[SolverState] = SingleSlotQueue()
    # In your real app, start your algorithm thread and call ch.publish(mutable.snapshot())
    t = threading.Thread(target=demo_producer, args=(ch,), daemon=True)
    t.start()
    try:
        ui_loop(ch)
    except KeyboardInterrupt:
        ch.close()

if __name__ == "__main__":
    run()
