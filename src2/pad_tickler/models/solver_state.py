from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable, Tuple, List
import threading, time


# ---------- Stats for a single block ----------
@dataclass
class BlockStats:
    tries: int = 0
    positives: int = 0
    negatives: int = 0
    confirmed_hits: int = 0
    notes: List[str] = field(default_factory=list)


# ---------- Immutable snapshot (for UI/events) ----------
@dataclass(frozen=True, slots=True)
class SolverState:
    pad_block: bytes = field(default=b"")

    ciphertext_n_1_prime: Tuple[bytes, ...] = field(default_factory=tuple)
    ciphertext_n: Tuple[bytes, ...] = field(default_factory=tuple)
    intermediate_n: Tuple[bytes, ...] = field(default_factory=tuple)
    plaintext_n: Tuple[bytes, ...] = field(default_factory=tuple)

    block_stats: List[BlockStats] = field(default_factory=list)
    i: int = 0
    k: int = 0
    g: int = 0
    block_size: int = 16

    version: int = 0
    ts: float = field(default_factory=time.time)

    def __post_init__(self):
        def to_block_tuple(name: str, seq: Iterable[bytes | bytearray]) -> Tuple[bytes, ...]:
            blocks = []
            for idx, b in enumerate(seq):
                bb = bytes(b)
                if len(bb) != self.block_size:
                    raise ValueError(f"{name}[{idx}] length {len(bb)} != block_size {self.block_size}")
                blocks.append(bb)
            return tuple(blocks)

        object.__setattr__(self, "ciphertext_n_1_prime",
                           to_block_tuple("ciphertext_n_1_prime", self.ciphertext_n_1_prime))
        object.__setattr__(self, "ciphertext_n",
                           to_block_tuple("ciphertext_n", self.ciphertext_n))
        object.__setattr__(self, "intermediate_n",
                           to_block_tuple("intermediate_n", self.intermediate_n))
        object.__setattr__(self, "plaintext_n",
                           to_block_tuple("plaintext_n", self.plaintext_n))

        pb = self.pad_block or (b"\x00" * self.block_size)
        if len(pb) != self.block_size:
            raise ValueError(f"pad_block length {len(pb)} != block_size {self.block_size}")
        object.__setattr__(self, "pad_block", bytes(pb))


# ---------- Mutable working state (for the algorithm) ----------
@dataclass(slots=True)
class MutableSolverState:
    pad_block: bytearray = field(default_factory=bytearray)              # single block

    ciphertext_n_1_prime: list[bytearray] = field(default_factory=list)  # list of blocks
    ciphertext_n: list[bytearray] = field(default_factory=list)
    intermediate_n: list[bytearray] = field(default_factory=list)
    plaintext_n: list[bytearray] = field(default_factory=list)

    i: int = 0
    k: int = 0
    g: int = 0
    block_size: int = 16

    version: int = 0
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False, compare=False)

    def __post_init__(self):
        # Normalize blocks to correct size and type.
        def normalize_list(name: str, lst: list[bytearray]) -> None:
            for idx, b in enumerate(lst):
                if not isinstance(b, (bytearray, bytes)):
                    raise TypeError(f"{name}[{idx}] must be bytes/bytearray")
                bb = bytearray(b)  # copy to mutable
                if len(bb) != self.block_size:
                    raise ValueError(f"{name}[{idx}] length {len(bb)} != block_size {self.block_size}")
                lst[idx] = bb

        with self._lock:
            normalize_list("ciphertext_n_1_prime", self.ciphertext_n_1_prime)
            normalize_list("ciphertext_n", self.ciphertext_n)
            normalize_list("intermediate_n", self.intermediate_n)
            normalize_list("plaintext_n", self.plaintext_n)

            if not self.pad_block:
                self.pad_block = bytearray(self.block_size)
            elif len(self.pad_block) != self.block_size:
                raise ValueError(f"pad_block length {len(self.pad_block)} != block_size {self.block_size}")

    # ---- Mutators (examples) ----
    def set_byte(self, which: str, block_idx: int, byte_idx: int, value: int) -> None:
        """which ∈ {'ciphertext_n_1_prime','ciphertext_n','intermediate_n','plaintext_n','pad_block'}"""
        with self._lock:
            if which == "pad_block":
                target = self.pad_block
            else:
                target = getattr(self, which)[block_idx]
            if not (0 <= byte_idx < self.block_size):
                raise IndexError("byte_idx out of range")
            target[byte_idx] = value & 0xFF
            self.version += 1

    def ensure_blocks(self, count: int) -> None:
        """Ensure each list has at least `count` blocks allocated (zeroed)."""
        with self._lock:
            def grow(lst: list[bytearray]):
                while len(lst) < count:
                    lst.append(bytearray(self.block_size))
            for lst in (self.ciphertext_n_1_prime, self.ciphertext_n, self.intermediate_n, self.plaintext_n):
                grow(lst)

    # ---- Snapshot handoff to UI ----
    def snapshot(self) -> SolverState:
        with self._lock:
            return SolverState(
                ciphertext_n_1_prime=tuple(bytes(b) for b in self.ciphertext_n_1_prime),
                pad_block=bytes(self.pad_block),
                ciphertext_n=tuple(bytes(b) for b in self.ciphertext_n),
                intermediate_n=tuple(bytes(b) for b in self.intermediate_n),
                plaintext_n=tuple(bytes(b) for b in self.plaintext_n),
                i=self.i, k=self.k, g=self.g,
                block_size=self.block_size,
                version=self.version,
            )
