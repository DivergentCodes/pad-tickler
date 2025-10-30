import traceback

from fastapi import FastAPI, APIRouter, HTTPException
import structlog

from . import crypto, models
from .utils import b64_encode, b64_decode

log = structlog.get_logger(
    processors=[
        structlog.processors.JSONRenderer(indent=2),
    ],
)
log.info("logger initialized")

# Create the FastAPI app
app = FastAPI(title="Padding Oracle Demo API")

# Create the router for API endpoints
router = APIRouter()


def encrypt(plaintext: str) -> bytes:
    plaintext = plaintext.encode("utf-8")
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
    return ciphertext


def build_encrypted_response(plaintext: str) -> models.EncryptResponse:
    """ Build a response with the encrypted ciphertext of the given plaintext. """
    ct = encrypt(plaintext)
    return models.EncryptResponse(
        alg=crypto.CipherSuite.AES_128_CBC.value,
        ciphertext_b64=b64_encode(ct),
        ciphertext_hex=ct.hex(),
    )


@router.get("/demo1", response_model=models.EncryptResponse)
def demo1():
    """ Single block with static IV and ciphertext.
    """
    plaintext = "Hello, world!"
    return build_encrypted_response(plaintext=plaintext)


@router.get("/demo2", response_model=models.EncryptResponse)
def demo2():
    """ Base64 encoded ciphertext with 5 blocks and a static IV.
    Each plaintext block is 16 bytes of the same character.
    """
    plaintext = (
        "aaaaaaaaaaaaaaaa"
        "bbbbbbbbbbbbbbbb"
        "cccccccccccccccc"
        "dddddddddddddddd"
        "eeeeeeeeeeeeeeee"
    )
    return build_encrypted_response(plaintext=plaintext)


@router.get("/demo3", response_model=models.EncryptResponse)
def demo3():
    """ Longer Base64 encoded ciphertext with a static IV. """
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

    return build_encrypted_response(plaintext=plaintext)


@router.post("/encrypt", response_model=models.EncryptResponse)
def encrypt_api(req: models.EncryptRequest):
    """ Encrypt the given plaintext and return the ciphertext. """
    try:
        plaintext = b64_decode(req.plaintext_b64)
        ciphertext = encrypt(plaintext)
        cipher = crypto.CipherSuite.AES_128_CBC.value
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
    """ Validate the given ciphertext and return the plaintext.
    This is the endpoint that is vulnerable to the padding oracle attack.
    """
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


# Include the router in the app (after all routes are defined)
app.include_router(router, prefix="/api")
