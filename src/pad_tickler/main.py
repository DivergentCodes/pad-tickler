import click
import threading

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.solver import demo_producer
from pad_tickler.ui import ui_loop


@click.command()
def run():
    """Minimal Rich/Click UI that renders latest StateSnapshot snapshots."""
    state_queue: SingleSlotQueue[StateSnapshot] = SingleSlotQueue()
    # In your real app, start your algorithm thread and call ch.publish(mutable.snapshot())
    t = threading.Thread(target=demo_producer, args=(state_queue,), daemon=True)
    t.start()
    try:
        ui_loop(state_queue)
    except KeyboardInterrupt:
        state_queue.close()

if __name__ == "__main__":
    run()
