from pydantic import BaseModel

from . import crypto


class EncryptRequest(BaseModel):
    plaintext_b64: str


class EncryptResponse(BaseModel):
    alg: crypto.CipherSuite
    ciphertext_b64: str
    ciphertext_hex: str


class ValidateRequest(BaseModel):
    alg: crypto.CipherSuite
    ciphertext_b64: bytes


class ValidateResponse(BaseModel):
    valid: bool
