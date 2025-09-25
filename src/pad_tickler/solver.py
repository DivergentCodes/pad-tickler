import random
import time

from pad_tickler.event_snapshot import SolverState
from pad_tickler.event_queue import SingleSlotQueue


def demo_producer(ch: SingleSlotQueue[SolverState], blocks: int = 3, block_size: int = 16):
    plaintext = [bytearray(block_size) for _ in range(blocks)]
    event_version = 0
    for bi in range(blocks):
        for byte_i in range(block_size - 1, -1, -1):
            # simulate discovery
            time.sleep(0.03)  # ~33 FPS max
            plaintext[bi][byte_i] = random.randint(32, 126)
            event_version += 1
            snap = SolverState(
                event_version=event_version,
                block_size=block_size,
                block_index_n=bi,
                byte_index_i=byte_i,
                byte_value_g=random.randint(32, 126),
                pad_length_k=byte_i + 1,
                ciphertext_n=tuple(bytes(b) for b in plaintext),
                ciphertext_n_1_prime=tuple(bytes(b) for b in plaintext),
                intermediate_n=tuple(bytes(b) for b in plaintext),
                plaintext_n=tuple(bytes(b) for b in plaintext),
            )
            ch.publish(snap)
    ch.close()
