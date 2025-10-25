import threading
import time

import click
import requests

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.solver import solve_message
from pad_tickler.ui import ui_loop
from pad_tickler.utils import b64_decode, b64_encode


@click.group()
def cli():
    pass


def submit_guess(prev_block: bytes, target_block: bytes) -> bool:
    """ Submit a padding guess to the oracle (demo API) to validate the given ciphertext. """
    ciphertext = prev_block + target_block
    ciphertext_b64 = b64_encode(ciphertext)
    payload = {
        "alg": "AES-128-CBC",
        "ciphertext_b64": ciphertext_b64
    }
    try:
        response = requests.post("http://127.0.0.1:8000/api/validate", json=payload, timeout=10)
        time.sleep(0.01)  # Small delay to prevent overwhelming the server
        return response.status_code == 200
    except Exception as e:
        print(f"Request failed: {e}")
        return False


def solver(ciphertext: bytes):
    """Run the real padding oracle solver against a remote service."""
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