import base64
import logging
import traceback

from fastapi import APIRouter, HTTPException
import structlog

from . import crypto, models

log = structlog.get_logger()

router = APIRouter()


@router.post("/encrypt", response_model=models.EncryptResponse)
def encrypt(req: models.EncryptRequest):
    try:
        plaintext = req.plaintext

        cipher = crypto.CipherSuite.AES_128_CBC.value
        key = crypto.get_key(cipher)
        iv = crypto.get_iv(cipher, random=False)
        log.info("encrypting", plaintext=plaintext, cipher=cipher, key=key, iv=iv)

        ciphertext = crypto.encrypt(plaintext, cipher, key, iv)

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
        ciphertext_b64 = req.ciphertext_b64
        ciphertext = base64.b64decode(ciphertext_b64)

        cipher = crypto.CipherSuite.AES_128_CBC.value
        key = crypto.get_key(cipher)
        iv = crypto.get_iv(cipher, random=False)
        log.info("decrypting", cipher=cipher, key=key, iv=iv)

        plaintext = crypto.decrypt(ciphertext, cipher, key, iv)
        log.info("decrypted", plaintext=plaintext)

        return models.ValidateResponse(
            valid=True,
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"{e}")
