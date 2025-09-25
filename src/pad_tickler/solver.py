import random
import time

from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.state_queue import SingleSlotQueue


def demo_producer(state_queue: SingleSlotQueue[StateSnapshot], blocks: int = 6, block_size: int = 16):
    # Generate random blocks for the initial demo state.
    plaintext = [[random.randint(0, 255) for _ in range(block_size)] for _ in range(blocks)]
    intermediate = [[random.randint(0, 255) for _ in range(block_size)] for _ in range(blocks)]
    ciphertext = [[random.randint(0, 255) for _ in range(block_size)] for _ in range(blocks)]
    ciphertext_1_prime = [[random.randint(0, 255) for _ in range(block_size)] for _ in range(blocks)]

    # Simulate the discovery process, updating the state values.
    state_version = 0
    for block_n in range(blocks):
        for byte_i in range(block_size - 1, -1, -1):
            time.sleep(0.03)  # ~33 FPS max
            state_version += 1

            # Update the value of the current byte in each block.
            plaintext[block_n][byte_i] = random.randint(0, 255)
            intermediate[block_n][byte_i] = random.randint(0, 255)
            ciphertext[block_n][byte_i] = random.randint(0, 255)
            ciphertext_1_prime[block_n][byte_i] = random.randint(0, 255)

            # Create a new snapshot of the state.
            snapshot = StateSnapshot(
                state_version=state_version,
                block_count=len(plaintext),
                block_size=block_size,
                block_index_n=block_n,
                byte_index_i=byte_i,
                byte_value_g=random.randint(0, 255),
                pad_length_k=byte_i + 1,
                ciphertext_n=tuple(bytes(b) for b in ciphertext),
                ciphertext_n_1_prime=tuple(bytes(b) for b in ciphertext_1_prime),
                intermediate_n=tuple(bytes(b) for b in intermediate),
                plaintext_n=tuple(bytes(b) for b in plaintext),
            )

            state_queue.publish(snapshot)

    state_queue.close()
