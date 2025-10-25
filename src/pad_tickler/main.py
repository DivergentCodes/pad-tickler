import threading

import click
import requests

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.solver import solve_message, submit_guess
from pad_tickler.ui import ui_loop
from pad_tickler.utils import b64_decode


@click.group()
def cli():
    pass


def encrypt(plaintext_b64: str) -> str:
    """ Use the demo API to get ciphertext for the given plaintext. """
    payload = {
        "plaintext_b64": plaintext_b64
    }
    response = requests.post("http://127.0.0.1:8000/api/encrypt", json=payload)
    if response.status_code != 200:
        raise ValueError(f"Failed to encrypt plaintext: {response.status_code} {response.text}")
    return response.json()["ciphertext_b64"]


def solver(ciphertext: bytes):
    """Run the real padding oracle solver against a remote service."""
    # In the real app, start the algorithm thread and call ch.publish(mutable.snapshot())
    state_queue: SingleSlotQueue[StateSnapshot] = SingleSlotQueue()
    t = threading.Thread(target=solve_message, args=(submit_guess, state_queue, ciphertext), daemon=True)
    t.start()
    try:
        ui_loop(state_queue)
    except KeyboardInterrupt:
        state_queue.close()


def fetch_demo_data(endpoint: str) -> bytes:
    """ Fetch the demo data from the given test endpoint. """
    response = requests.get(endpoint)
    if response.status_code != 200:
        raise ValueError(f"Failed to get {endpoint}: {response.status_code} {response.text}")
    data = response.json()
    return b64_decode(data["ciphertext_b64"])


@cli.command()
def demo1():
    """Run with data from the demo1 endpoint."""
    ciphertext = fetch_demo_data("http://127.0.0.1:8000/api/demo1")
    solver(ciphertext)


@cli.command()
def demo2():
    """Run with data from the demo2 endpoint."""
    ciphertext = fetch_demo_data("http://127.0.0.1:8000/api/demo2")
    solver(ciphertext)


@cli.command()
def demo3():
    """Run with data from the demo3 endpoint."""
    ciphertext = fetch_demo_data("http://127.0.0.1:8000/api/demo3")
    solver(ciphertext)


if __name__ == "__main__":
    cli()