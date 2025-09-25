from dataclasses import dataclass, field
from typing import Tuple

@dataclass(frozen=True, slots=True)
class StateSnapshot:
    """ Minimal immutable snapshot of solver state. """
    state_version: int
    block_count: int
    block_size: int
    block_index_n: int
    byte_index_i: int
    byte_value_g: int
    pad_length_k: int

    # Original ciphertext block n.
    ciphertext_n: Tuple[bytes, ...] = field(default_factory=tuple)
    # Scratch of ciphertext block n-1 to find the corresponding intermediate block.
    ciphertext_n_1_prime: Tuple[bytes, ...] = field(default_factory=tuple)
    # Intermediate block n to find the corresponding plaintext block.
    intermediate_n: Tuple[bytes, ...] = field(default_factory=tuple)
    # Discovered plaintext block n.
    plaintext_n: Tuple[bytes, ...] = field(default_factory=tuple)
