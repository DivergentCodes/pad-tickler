import os
import base64
import pathlib
from typing import Optional
from enum import Enum

from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import structlog


log = structlog.get_logger()

KEY_DIR = pathlib.Path(__file__).parent / "keys"
KEY_DIR.mkdir(parents=True, exist_ok=True)

class CipherSuite(str, Enum):
    AES_128_CBC = "AES-128-CBC"
    AES_128_ECB = "AES-128-ECB"
    AES_256_CBC = "AES-256-CBC"
    AES_256_ECB = "AES-256-ECB"
    DES_CBC = "DES-CBC"
    DES_ECB = "DES-ECB"
    DES3_CBC = "DES3-CBC"
    DES3_ECB = "DES3-ECB"

    def __str__(self):
        return self.value


def get_key(algorithm: CipherSuite) -> bytes:
    """Returns a key for the given algorithm.
    If the key file does not exist, it creates a new key and saves it to the key file."""
    keyfile = KEY_DIR / f"{algorithm}.key"
    key = None
    if not os.path.exists(keyfile):
        match algorithm:
            case CipherSuite.AES_128_CBC.value:
                key = os.urandom(16)
            case CipherSuite.AES_128_ECB.value:
                key = os.urandom(16)
            case CipherSuite.AES_256_CBC.value:
                key = os.urandom(32)
            case CipherSuite.AES_256_ECB.value:
                key = os.urandom(32)
            case CipherSuite.DES_CBC.value:
                key = os.urandom(8)
            case CipherSuite.DES_ECB.value:
                key = os.urandom(8)
            case CipherSuite.DES3_CBC.value:
                key = os.urandom(24)
            case CipherSuite.DES3_ECB.value:
                key = os.urandom(24)
            case _:
                raise ValueError(f"Invalid algorithm: {algorithm}")
        with open(keyfile, "wb") as f:
            f.write(key)
    else:
        with open(keyfile, "rb") as f:
            key = f.read()
    return key


def get_iv(algorithm: CipherSuite, random: bool = True) -> bytes:
    """Returns a random IV for the given algorithm.
    If the IV file does not exist, it creates a new IV and saves it to the IV file."""
    ivfile = KEY_DIR / f"{algorithm}.iv"
    iv = None

    if random or not os.path.exists(ivfile):
        match algorithm:
            case CipherSuite.AES_128_CBC.value:
                iv = os.urandom(16)
            case CipherSuite.AES_128_ECB.value:
                iv = os.urandom(16)
            case CipherSuite.AES_256_CBC.value:
                iv = os.urandom(16)
            case CipherSuite.AES_256_ECB.value:
                iv = os.urandom(16)
            case CipherSuite.DES_CBC.value:
                iv = os.urandom(8)
            case CipherSuite.DES_ECB.value:
                iv = os.urandom(8)
            case CipherSuite.DES3_CBC.value:
                iv = os.urandom(8)
            case CipherSuite.DES3_ECB.value:
                iv = os.urandom(8)
            case _:
                raise ValueError(f"Invalid algorithm: {algorithm}")

    if random:
        return iv

    if not os.path.exists(ivfile):
        with open(ivfile, "wb") as f:
            f.write(iv)
        return iv

    with open(ivfile, "rb") as f:
        iv = f.read()
    return iv


def encrypt(algorithm: CipherSuite, key: bytes, iv: bytes, plaintext: str) -> bytes:
    """ Encrypts the plaintext using the given algorithm and key.
    If the algorithm is CBC, it uses the given IV.
    If the algorithm is ECB, it does not use an IV.
    """

    plaintext_bytes = plaintext.encode("utf-8")

    padder_128 = padding.PKCS7(128).padder()
    padder_64 = padding.PKCS7(64).padder()

    try:
        match algorithm:
            case CipherSuite.AES_128_CBC.value:
                padder = padder_128
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            case CipherSuite.AES_128_ECB.value:
                padder = padder_128
                cipher = Cipher(algorithms.AES(key), modes.ECB())
            case CipherSuite.AES_256_CBC.value:
                padder = padder_128
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            case CipherSuite.AES_256_ECB.value:
                padder = padder_128
                cipher = Cipher(algorithms.AES(key), modes.ECB())
            case CipherSuite.DES_CBC.value:
                padder = padder_64
                cipher = Cipher(algorithms.DES(key), modes.CBC(iv))
            case CipherSuite.DES_ECB.value:
                padder = padder_64
                cipher = Cipher(algorithms.DES(key), modes.ECB())
            case CipherSuite.DES3_CBC.value:
                padder = padder_64
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            case CipherSuite.DES3_ECB.value:
                padder = padder_64
                cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
            case _:
                raise ValueError(f"Invalid algorithm: {algorithm}")
    except Exception as e:
        log.error("encryption failed", error=e)
        raise e

    padded = padder.update(plaintext_bytes) + padder.finalize()
    encryptor = cipher.encryptor()

    # Prepend the IV to the ciphertext.
    ciphertext = iv + encryptor.update(padded) + encryptor.finalize()
    return ciphertext


def decrypt(algorithm: CipherSuite, key: bytes, ciphertext: bytes) -> str:
    """ Decrypts the ciphertext using the given algorithm and key.
    If the algorithm is CBC, it uses the given IV.
    If the algorithm is ECB, it does not use an IV.
    """

    try:
        match algorithm:
            case CipherSuite.AES_128_CBC.value:
                iv = ciphertext[:16]
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            case CipherSuite.AES_128_ECB.value:
                iv = None
                cipher = Cipher(algorithms.AES(key), modes.ECB())
            case CipherSuite.AES_256_CBC.value:
                iv = ciphertext[:16]
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            case CipherSuite.AES_256_ECB.value:
                iv = None
                cipher = Cipher(algorithms.AES(key), modes.ECB())
            case CipherSuite.DES_CBC.value:
                iv = ciphertext[:8]
                cipher = Cipher(algorithms.DES(key), modes.CBC(iv))
            case CipherSuite.DES_ECB.value:
                iv = None
                cipher = Cipher(algorithms.DES(key), modes.ECB())
            case CipherSuite.DES3_CBC.value:
                iv = ciphertext[:8]
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            case CipherSuite.DES3_ECB.value:
                iv = None
                cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
            case _:
                raise ValueError(f"Invalid algorithm: {algorithm}")
    except Exception as e:
        log.error("decryption failed", error=e)
        raise e

    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(padded) + unpadder.finalize()
    return unpadded.decode("utf-8")
