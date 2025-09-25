import click
import random
import threading
import time

from pad_tickler.event_snapshot import SolverState
from pad_tickler.event_queue import SingleSlotQueue
from pad_tickler.ui import ui_loop


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
