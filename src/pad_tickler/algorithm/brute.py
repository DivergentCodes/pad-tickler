import base64
from dataclasses import dataclass, field
import secrets
from typing import Callable

import requests


RESPONSE_ERRORS = {
    "_total": 0,
}


def z16() -> bytearray:
    return bytearray(16)


def random_16() -> bytearray:
    return bytearray(secrets.token_bytes(16))


@dataclass
class BlockState:
    ciphertext_n_1_prime: bytearray = field(default_factory=z16)
    pad_block: bytearray = field(default_factory=z16)
    ciphertext_n: bytearray = field(default_factory=z16)
    intermediate_n: bytearray = field(default_factory=z16)
    plaintext_n: bytearray = field(default_factory=z16)
    i: int = 0
    k: int = 0
    g: int = 0
    block_size: int = 16


def pretty_block(block: bytearray) -> str:
    return " ".join([f"{b:02x}" for b in block])


def show_block_state(block_state: BlockState):
    print(f"Guesses (Cₙ₋₁′):    {pretty_block(block_state.ciphertext_n_1_prime)}")
    print(f"Pad block (k):      {pretty_block(block_state.pad_block)}")
    print(f"Ciphertext (Cₙ):    {pretty_block(block_state.ciphertext_n)}")
    print(f"Intermediate (Iₙ):  {pretty_block(block_state.intermediate_n)}")
    print(f"Plaintext (Pₙ):     {pretty_block(block_state.plaintext_n)}")


def gen_pad_block(k: int, block_size: int) -> bytearray:
    """ Set the last k bytes to k """
    pad_block = bytearray(block_size)
    pad_block[-k:] = [k] * k
    return pad_block


def brute_force_block(ciphertext_n: bytearray, oracle_ok: Callable[[BlockState], bool]):

    # Iterate over the blocks backwards.
    block_size = 16
    block_count = len(ciphertext_n) // block_size
    for n in reversed(range(block_count)):
        print(f"\n[*] n={n}")
        # breakpoint()
        block_state = BlockState()
        block_state.ciphertext_n = ciphertext_n
        block_state.k = 1 # padding length k

        show_block_state(block_state)

        # Iterate over the bytes in the block backwards.
        for i in reversed(range(block_state.block_size)):
            block_state.i = i
            print(f"\n[*] n={n} | i={block_state.i}")
            # breakpoint()

            # Set new padding k
            block_state.pad_block = gen_pad_block(block_state.k, block_state.block_size)

            # Iterate C' through guesses g
            for g in range(256):
                block_state.g = g
                block_state.ciphertext_n_1_prime[block_state.i] = block_state.g
                print(f"\n[*] n={n} | i={block_state.i} | k={block_state.k} | g={block_state.g:02x}")

                if oracle_ok(block_state):
                    # Iₙ[i] = k ⊕ g, intermediate = padding XOR guess
                    block_state.intermediate_n[block_state.i] = block_state.k ^ block_state.g
                    # Pₙ[i] = Cₙ[i] ⊕ Iₙ[i], plaintext = ciphertext XOR intermediate
                    block_state.plaintext_n[block_state.i] = block_state.ciphertext_n[block_state.i] ^ block_state.intermediate_n[block_state.i]
                    #show_block_state(block_state)
                    #breakpoint()
                    break

            show_block_state(block_state)
            block_state.k += 1

def oracle_test(block_state: BlockState) -> bool:
    #return secrets.choice(range(0, 100)) <= 10
    prior = bytearray(block_state.ciphertext_n_1_prime)
    target = bytearray(block_state.ciphertext_n)
    payload = prior + target
    print(f"Payload: {pretty_block(payload)}")
    payload_b64 = base64.b64encode(payload).decode("utf-8")
    response = requests.post("http://localhost:8000/api/validate", json={"ciphertext_b64": payload_b64})

    if response.status_code == 200:
        return False

    detail = str(response.json().get("detail", "")).split(":")[-1].strip()
    RESPONSE_ERRORS["_total"] += 1
    RESPONSE_ERRORS[detail] = RESPONSE_ERRORS.get(detail, 0) + 1
    print(response.json())
    return False

    # If the error is something other than "Invalid padding bytes.", then the ciphertext padding is valid.
    success = detail != 'Invalid padding bytes.'
    return success


if __name__ == "__main__":
    b64 = {
        "alg": "AES-128-CBC",
        "iv_b64": "L4GNQGz48epdIiVCc2MboQ==",
        "ciphertext_b64": "mrH+LB63tYaVm7ZG3uFoaw=="
    }

    iv = bytearray(base64.b64decode(b64["iv_b64"]))
    ciphertext = bytearray(base64.b64decode(b64["ciphertext_b64"]))
    full_ciphertext = iv + ciphertext

    print(f"IV ({len(iv)} bytes):\t\t\t{pretty_block(iv)}")
    print(f"Ciphertext ({len(ciphertext)} bytes):\t\t{pretty_block(ciphertext)}")
    print(f"Full ciphertext ({len(full_ciphertext)} bytes):\t{pretty_block(full_ciphertext)}")

    brute_force_block(full_ciphertext, oracle_test)

    # Show the response errors.
    from pprint import pprint
    print("-" * 80)
    print("Response errors:")
    pprint(RESPONSE_ERRORS)
    print("-" * 80)
    print(f"Total responses: {sum(RESPONSE_ERRORS.values())}")