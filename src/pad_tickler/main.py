from concurrent.futures import ThreadPoolExecutor

import click
import requests

from pad_tickler.demo_guess import submit_guess as demo_submit_guess
from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.solver import solve_message
from pad_tickler.ui import ui_loop
from pad_tickler.utils import b64_decode, load_ciphertext, load_guess_fn, \
    bytestring_from_list_of_blocks, strip_plaintext_padding, \
    CiphertextFormat, SubmitGuessFn


@click.group()
def cli():
    pass


def solver(submit_guess: SubmitGuessFn, ciphertext: bytes):
    """Run the real padding oracle solver against a remote service."""
    state_queue: SingleSlotQueue[StateSnapshot] = SingleSlotQueue()

    with ThreadPoolExecutor() as executor:
        future = executor.submit(solve_message, submit_guess, state_queue, ciphertext)

        try:
            ui_loop(state_queue)
        except KeyboardInterrupt:
            state_queue.close()

        plaintext = future.result()
        plaintext = bytestring_from_list_of_blocks(plaintext)
        plaintext = strip_plaintext_padding(plaintext)
        return plaintext


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
    plaintext = solver(demo_submit_guess, ciphertext)
    print(plaintext)
    #breakpoint()


@cli.command()
def demo2():
    """Run with data from the demo2 endpoint."""
    ciphertext = fetch_demo_data("http://127.0.0.1:8000/api/demo2")
    plaintext = solver(demo_submit_guess, ciphertext)
    print(plaintext)


@cli.command()
def demo3():
    """Run with data from the demo3 endpoint."""
    ciphertext = fetch_demo_data("http://127.0.0.1:8000/api/demo3")
    plaintext = solver(demo_submit_guess, ciphertext)
    print(plaintext)


@cli.command()
@click.option("--ciphertext-path", "-c", required=True, type=click.Path(exists=True))
@click.option("--ciphertext-format", "-f", type=click.Choice(["b64", "b64_urlsafe", "hex", "raw"]), default="b64")
@click.option("--guess-fn", "-g", required=True, type=click.Path(exists=True))
def solve(ciphertext_path: str, ciphertext_format: CiphertextFormat, guess_fn: str):
    """Solve a given ciphertext with a user defined guess function."""
    ciphertext = load_ciphertext(ciphertext_path, ciphertext_format)
    submit_guess_fn = load_guess_fn(guess_fn)
    plaintext = solver(submit_guess_fn, ciphertext)
    print(plaintext)

if __name__ == "__main__":
    cli()