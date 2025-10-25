# Pad Tickler

Pad Tickler is a CLI tool for executing Padding Oracle attacks against arbitrary targets.

It accepts a user-defined Python module with a `submit_guess()` function to send padding guesses to the target. Targets can include web API endpoints, physical devices connected over a serial port, local binaries, and anything else that Python can touch.

There are several demos to show how the tool (and padding oracles) work.

## Usage

Running the demos locally.

```sh
uv sync
uv run python -m demo_api.main &
uv run python src/pad_tickler/main.py demo1
uv run python src/pad_tickler/main.py demo2
uv run python src/pad_tickler/main.py demo3
```

Running against a target in local development requires supplying a Python module with your `submit_guess` function and a ciphertext file as binary, base64, URL-safe base64, or hex data.

```sh
uv run python src/pad_tickler/main.py solve -g my_guess.py -c ciphertext.hex -f hex
```

## User-Defined Guess Function

To support arbitrary padding oracle targets, users define their own
`submit_guess` function with the following signature:

```py
def submit_guess(prev_block: bytes, target_block: bytes) -> bool:
```

- `prev_block`: The ciphertext prime block before the target block `Cₙ₋₁′`.
- `target_block`: The target ciphertext block.
- `bool`: True if the padding guess worked, false if there was an error.

A full demo guess function is in [demo_guess.py](src/pad_tickler/demo_guess.py).
