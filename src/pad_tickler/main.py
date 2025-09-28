import threading

import click
import requests

from pad_tickler.state_queue import SingleSlotQueue
from pad_tickler.state_snapshot import StateSnapshot
from pad_tickler.solver import demo_producer, solve_message, submit_http
from pad_tickler.ui import ui_loop
from pad_tickler.utils import b64_decode, b64_encode


@click.group()
def cli():
    pass


def encrypt(plaintext_b64: str) -> str:
    payload = {
        "plaintext_b64": plaintext_b64
    }
    response = requests.post("http://127.0.0.1:8000/api/encrypt", json=payload)
    if response.status_code != 200:
        raise ValueError(f"Failed to encrypt plaintext: {response.status_code} {response.text}")
    return response.json()["ciphertext_b64"]


def values1() -> tuple[bytes, bytes]:
    iv_hex = "2f818d406cf8f1ea5d22254273631ba1"
    ct_hex = "9ab1fe2c1eb7b586959bb646dee1686b"
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    return iv, ct


def values2() -> tuple[bytes, bytes]:
    ct_long3_b64 = "L4GNQGz48epdIiVCc2Mboflt7i8qi5spwF2Xvyl2tWuqWd9g3uSgl5gGmupYOjjihRV9o0A1Y5c0VRb/b/roDa9ic8EgnmN0GGhN5x8FrSte5fji98f1d25KfgWgSYoL"
    ct = b64_decode(ct_long3_b64)
    iv_hex = ct[:16].hex()
    ct_hex = ct[16:].hex()
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    return iv, ct


def values3() -> tuple[bytes, bytes]:
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
    ct_b64 = encrypt(pt_b64)
    ct = b64_decode(ct_b64)
    iv = ct[:16]
    ct = ct[16:]
    return iv, ct


@cli.command()
def demo():
    """Run the demo with simulated padding oracle attack."""
    state_queue: SingleSlotQueue[StateSnapshot] = SingleSlotQueue()
    # In your real app, start your algorithm thread and call ch.publish(mutable.snapshot())
    t = threading.Thread(target=demo_producer, args=(state_queue,), daemon=True)
    t.start()
    try:
        ui_loop(state_queue)
    except KeyboardInterrupt:
        state_queue.close()


@cli.command()
def solver():
    """Run the real padding oracle solver against a remote service."""
    state_queue: SingleSlotQueue[StateSnapshot] = SingleSlotQueue()
    # In your real app, start your algorithm thread and call ch.publish(mutable.snapshot())

    #iv, ct = values1()
    iv, ct = values2()
    # iv, ct = values3()

    ciphertext = iv + ct

    t = threading.Thread(target=solve_message, args=(submit_http, state_queue, ciphertext), daemon=True)
    t.start()
    try:
        ui_loop(state_queue)
    except KeyboardInterrupt:
        state_queue.close()


if __name__ == "__main__":
    cli()