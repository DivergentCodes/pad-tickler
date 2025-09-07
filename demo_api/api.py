import logging
import traceback

from fastapi import APIRouter, HTTPException
import structlog

from . import crypto, models
from .utils import b64_encode, b64_decode

log = structlog.get_logger(
    processors=[
        structlog.processors.JSONRenderer(indent=2),
    ],
)
log.info("logger initialized")

router = APIRouter()


@router.post("/encrypt", response_model=models.EncryptResponse)
def encrypt(req: models.EncryptRequest):
    try:
        plaintext = b64_decode(req.plaintext_b64)

        cipher = crypto.CipherSuite.AES_128_CBC.value
        key = crypto.get_key(cipher)
        iv = crypto.get_iv(cipher, random=False)

        ciphertext = crypto.encrypt(cipher, key, iv, plaintext)
        log.info(
            "encrypted",
            cipher=cipher,
            plaintext=plaintext,
            plaintext_hex=plaintext.hex(" "),

            key_hex=key.hex(),
            iv_hex=iv.hex(),
            ciphertext_hex=ciphertext.hex(" "),

            key_len=len(key),
            iv_len=len(iv),
            ciphertext_len=len(ciphertext),
        )

        return models.EncryptResponse(
            alg=cipher,
            ciphertext_b64=b64_encode(ciphertext),
            ciphertext_hex=ciphertext.hex(),
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"Encryption error: {e}")


@router.post("/validate", response_model=models.ValidateResponse)
def validate(req: models.ValidateRequest):
    cipher = crypto.CipherSuite.AES_128_CBC.value
    key = crypto.get_key(cipher)

    ciphertext_b64 = req.ciphertext_b64
    ciphertext = b64_decode(ciphertext_b64)

    if len(ciphertext) < 32:
        raise HTTPException(status_code=400, detail="Ciphertext must be at least 32 bytes long")

    ciphertext_n = ciphertext[-16:]
    ciphertext_n_1 = ciphertext[-32:-16]

    try:
        log.info(
            "decrypting",
            cipher=cipher,

            key_hex=key.hex(),
            ciphertext_hex=ciphertext.hex(),

            key_len=len(key),
            ciphertext_len=len(ciphertext),
        )

        plaintext = crypto.decrypt(cipher, key, ciphertext)
        log.info(
            "decrypted",
            plaintext=plaintext,
            plaintext_hex=plaintext.hex(),
        )

        return models.ValidateResponse(
            valid=True,
        )
    except Exception as e:
        if "Invalid padding bytes" in str(e):
            log.warn("invalid padding bytes", ciphertext_n=ciphertext_n.hex(), ciphertext_n_1=ciphertext_n_1.hex())
        else:
            traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"{e}")
