from pydantic import BaseModel

from . import crypto


class EncryptRequest(BaseModel):
    plaintext: str


class EncryptResponse(BaseModel):
    alg: crypto.CipherSuite
    iv_b64: str
    ciphertext_b64: str


class ValidateRequest(BaseModel):
    ciphertext_b64: str


class ValidateResponse(BaseModel):
    valid: bool