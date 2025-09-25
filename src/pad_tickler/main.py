import click
import threading

from pad_tickler.event_queue import SingleSlotQueue
from pad_tickler.event_snapshot import SolverState
from pad_tickler.solver import demo_producer
from pad_tickler.ui import ui_loop


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