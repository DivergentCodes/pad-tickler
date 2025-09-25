import click
import threading

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.solver import demo_producer, solve_message, submit_http
from pad_tickler.ui import ui_loop


@click.group()
def cli():
    pass


@cli.command()
def demo():
    """Run the demo with simulated padding oracle attack."""
    state_queue: SingleSlotQueue[StateSnapshot] = SingleSlotQueue()
    # In your real app, start your algorithm thread and call ch.publish(mutable.snapshot())
    t = threading.Thread(target=demo_producer, args=(state_queue,), daemon=True)
    t.start()
    try:
        ui_loop(state_queue)
    except KeyboardInterrupt:
        state_queue.close()


@cli.command()
def solver():
    """Run the real padding oracle solver against a remote service."""
    state_queue: SingleSlotQueue[StateSnapshot] = SingleSlotQueue()
    # In your real app, start your algorithm thread and call ch.publish(mutable.snapshot())

    ciphertext = bytes.fromhex("9ab1fe2c1eb7b586959bb646dee1686b")
    iv = bytes.fromhex("2f818d406cf8f1ea5d22254273631ba1")

    t = threading.Thread(target=solve_message, args=(submit_http, state_queue, iv, ciphertext), daemon=True)
    t.start()
    try:
        ui_loop(state_queue)
    except KeyboardInterrupt:
        state_queue.close()


if __name__ == "__main__":
    cli()