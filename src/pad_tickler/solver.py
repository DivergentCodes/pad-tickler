from typing import Tuple

from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.utils import SubmitGuessFn

MAX_POSSIBLE_STEPS = 0
CURRENT_STEP = 0
BYTES_FOUND = 0
BYTES_TOTAL = 0
COMPLETION_PERCENT = 0.00


def confirm_guess(submit: SubmitGuessFn, c_prev_prime: bytearray, c_target_block: bytes, pad_k: int) -> Tuple[bool, int]:
    """
    Flip a byte **outside** the last k bytes (i.e., index < 16 - k) and re-submit.
    If still valid, treat as a confirmed padding hit for this k.
    Returns (confirmed, flipped_idx).
    """
    block_size = len(c_target_block)
    flipped_idx = (block_size - pad_k - 1)
    if flipped_idx < 0:
        # Accept as confirmed when no non-tail byte to flip (like at k == block_size).
        return True, -1

    c_prev_prime2 = c_prev_prime[:]
    c_prev_prime2[flipped_idx] ^= 0x01
    is_confirmed = submit(bytes(c_prev_prime2), c_target_block)
    return is_confirmed, flipped_idx


def solve_message(
    submit: SubmitGuessFn,
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
    global MAX_POSSIBLE_STEPS, CURRENT_STEP, BYTES_FOUND, BYTES_TOTAL, COMPLETION_PERCENT

    try:
        assert len(ciphertext) % block_size == 0, "ciphertext must be block-aligned"

        # Break the ciphertext into blocks.
        ciphertext_blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
        block_count = len(ciphertext_blocks)

        # Initialize other sets of blocks.
        ciphertext_prime_blocks = [bytearray(block) for block in ciphertext_blocks]
        intermediate_blocks = [[None for _ in range(block_size)] for _ in range(block_count)]
        plaintext_blocks = [[None for _ in range(block_size)] for _ in range(block_count)]

        BYTES_TOTAL = len(ciphertext) - block_size  # Don't count IV bytes
        MAX_POSSIBLE_STEPS = 256 * block_size * (block_count - 1)  # Don't count IV
        BYTES_FOUND = 0
        CURRENT_STEP = 0
        state_version = 0

        # Solve each individual block
        # Skip the first block (IV) and only decrypt actual ciphertext blocks
        for block_index_n, ciphertext_n in enumerate(ciphertext_blocks[1:], start=1):
            skip_trivial_original = True

            # The previous block for decryption (IV for first block, previous ciphertext for others)
            ciphertext_prime_n1 = ciphertext_prime_blocks[block_index_n - 1]
            assert len(ciphertext_prime_n1) == block_size and len(ciphertext_n) == block_size

            # Storage for intermediate bytes I_i (fill right->left)
            intermediate_n = intermediate_blocks[block_index_n]

            # Create a new snapshot of the state.
            intermediate_i = block_size - 1 # Start from the last byte position in the block.
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

            # Iterate backwards over each byte in the block.
            # Padding length k is the number of bytes from the end of the block.
            for pad_length_k in range(1, block_size + 1):
                # Fill in the already-solved tail bytes from the intermediate block.
                for j in range(block_size - (pad_length_k - 1), block_size):
                    intermediate_i = intermediate_n[j]
                    if intermediate_i is None:
                        # Not solved yet (will happen only at start of each k).
                        continue
                    ciphertext_prime_n1[j] = intermediate_i ^ pad_length_k

                # Brute-force the new target byte at i = block_size - k, looking for the value
                # that produces valid padding and reveals the correct intermediate byte.
                byte_index_i = block_size - pad_length_k
                found = False
                for byte_value_g in range(256):
                    CURRENT_STEP += 1

                    # Skip trivial original only for k==1
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

                    # Submit the guess to the oracle.
                    is_valid_guess = submit(bytes(ciphertext_prime_n1), ciphertext_n)
                    if not is_valid_guess:
                        continue

                    # Confirm guess validity by flipping a non-tail byte.
                    confirmed, _ = confirm_guess(submit, ciphertext_prime_n1, ciphertext_n, pad_length_k)
                    if confirmed:
                        # Save the discovered intermediate byte.
                        intermediate_n[byte_index_i] = byte_value_g ^ pad_length_k
                        prev_block = ciphertext_blocks[block_index_n - 1]

                        # For CBC mode, plaintext = previous_ciphertext_block XOR intermediate
                        plaintext_blocks[block_index_n][byte_index_i] = prev_block[byte_index_i] ^ intermediate_n[byte_index_i]

                        found = True
                        BYTES_FOUND += 1
                        COMPLETION_PERCENT = BYTES_FOUND / BYTES_TOTAL * 100
                        break
                    else:
                        # Not confirmed. Likely a false positive.
                        continue

                if not found:
                    raise RuntimeError(f"No valid guess found at k={pad_length_k} (i={byte_index_i}); oracle not behaving like pure PKCS#7?")

        # Final state snapshot.
        state_version += 1
        snapshot = StateSnapshot(
            state_version=state_version,
            complete=True,
            block_count=block_count - 1,
            block_size=block_size,
            block_index_n=block_index_n,
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
