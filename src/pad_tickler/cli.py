from concurrent.futures import ThreadPoolExecutor

import click
import requests

from pad_tickler.demo_guess import submit_guess as demo_submit_guess
from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.solver import solve_message
from pad_tickler.ui import ui_loop
from pad_tickler.utils import (
    b64_decode,
    load_ciphertext,
    load_guess_fn,
    bytestring_from_list_of_blocks,
    strip_plaintext_padding,
    CiphertextFormat,
    SubmitGuessFn,
)


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
    """Fetch the demo data from the given test endpoint."""
    response = requests.get(endpoint)
    if response.status_code != 200:
        raise ValueError(
            f"Failed to get {endpoint}: {response.status_code} {response.text}"
        )
    data = response.json()
    return b64_decode(data["ciphertext_b64"])


@cli.command()
def demo1():
    """Run with data from the demo1 endpoint."""
    ciphertext = fetch_demo_data("http://127.0.0.1:8000/api/demo1")
    plaintext = solver(demo_submit_guess, ciphertext)
    print(plaintext)
    # breakpoint()


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
@click.option(
    "--ciphertext-format",
    "-f",
    type=click.Choice(["b64", "b64_urlsafe", "hex", "raw"]),
    default="b64",
)
@click.option("--guess-fn", "-g", required=True, type=click.Path(exists=True))
def solve(ciphertext_path: str, ciphertext_format: CiphertextFormat, guess_fn: str):
    """Solve a given ciphertext with a user defined guess function."""
    ciphertext = load_ciphertext(ciphertext_path, ciphertext_format)
    submit_guess_fn = load_guess_fn(guess_fn)
    plaintext = solver(submit_guess_fn, ciphertext)
    plaintext_path = f"{ciphertext_path}.plaintext"

    with open(plaintext_path, "wb") as f:
        f.write(plaintext)


@cli.command("demo-api")
@click.option("--host", default="127.0.0.1", help="Host to bind the server to")
@click.option("--port", default=8000, help="Port to bind the server to")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def demo_api(host: str, port: int, reload: bool):
    """Start the demo API server for testing padding oracle attacks."""
    try:
        import uvicorn
        from demo_api.api import app
    except ImportError as e:
        click.echo(f"Error: Demo API dependencies not available: {e}")
        click.echo("Install with: uv sync --group demo")
        raise click.Abort()

    click.echo(f"Starting demo API server on http://{host}:{port}")
    click.echo("Available endpoints:")
    click.echo("  - GET  /api/demo1  - Single block demo")
    click.echo("  - GET  /api/demo2  - Multi-block demo")
    click.echo("  - GET  /api/demo3  - Long text demo")
    click.echo("  - POST /api/encrypt - Encrypt plaintext")
    click.echo("  - POST /api/validate - Validate ciphertext (padding oracle)")
    click.echo("\nPress Ctrl+C to stop the server")

    if reload:
        # Use import string for reload mode
        uvicorn.run("demo_api.api:app", host=host, port=port, reload=True)
    else:
        # Use app object for non-reload mode (faster startup)
        uvicorn.run(app, host=host, port=port, reload=False)


if __name__ == "__main__":
    cli()
