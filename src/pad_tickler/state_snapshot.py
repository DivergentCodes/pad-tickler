from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True, slots=True)
class StateSnapshot:
    """Minimal immutable snapshot of solver state."""

    state_version: int
    complete: bool
    block_count: int
    block_size: int
    block_index_n: int
    byte_index_i: int
    byte_value_g: int
    pad_length_k: int

    ciphertext: Tuple[bytes | None, ...] = field(default_factory=tuple)
    ciphertext_prime: Tuple[bytes | None, ...] = field(default_factory=tuple)
    intermediate: Tuple[bytes | None, ...] = field(default_factory=tuple)
    plaintext: Tuple[bytes | None, ...] = field(default_factory=tuple)
