import base64
import logging
import traceback

from fastapi import APIRouter, HTTPException
import structlog

from . import crypto, models

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
        plaintext = req.plaintext

        cipher = crypto.CipherSuite.AES_128_CBC.value
        key = crypto.get_key(cipher)
        iv = crypto.get_iv(cipher, random=False)
        ciphertext = crypto.encrypt(plaintext, cipher, key, iv)
        log.info(
            "encrypted",
            cipher=cipher,
            plaintext=plaintext,
            plaintext_hex=plaintext.encode("utf-8").hex(),

            key_hex=key.hex(),
            iv_hex=iv.hex(),
            ciphertext_hex=ciphertext.hex(),

            key_len=len(key),
            iv_len=len(iv),
            ciphertext_len=len(ciphertext),
        )

        return models.EncryptResponse(
            alg=cipher,
            iv_b64=base64.b64encode(iv).decode(),
            ciphertext_b64=base64.b64encode(ciphertext).decode(),
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"Encryption error: {e}")


@router.post("/validate", response_model=models.ValidateResponse)
def validate(req: models.ValidateRequest):
    try:
        iv_b64 = req.iv_b64
        iv = base64.b64decode(iv_b64)
        ciphertext_b64 = req.ciphertext_b64
        ciphertext = base64.b64decode(ciphertext_b64)

        cipher = crypto.CipherSuite.AES_128_CBC.value
        key = crypto.get_key(cipher)
        log.info(
            "decrypting",
            cipher=cipher,

            key_hex=key.hex(),
            iv_hex=iv.hex(),
            ciphertext_hex=ciphertext.hex(),

            key_len=len(key),
            iv_len=len(iv),
            ciphertext_len=len(ciphertext),
        )

        plaintext = crypto.decrypt(ciphertext, cipher, key, iv)
        log.info(
            "decrypted",
            plaintext=plaintext,
            plaintext_hex=plaintext.encode("utf-8").hex(),
        )

        return models.ValidateResponse(
            valid=True,
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"{e}")
