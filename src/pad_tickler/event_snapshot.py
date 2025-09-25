from dataclasses import dataclass, field
from typing import Tuple

# ---- Minimal immutable snapshot (adapt to your SolverState) ----
@dataclass(frozen=True, slots=True)
class SolverState:
    version: int
    block_index: int
    byte_index: int
    block_size: int = 16
    plaintext_n: Tuple[bytes, ...] = field(default_factory=tuple)  # tuple of 16-byte blocks
