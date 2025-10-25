import base64
from typing import Union


def _as_bytes(
    data: Union[str, bytes, bytearray, memoryview],
    *,
    encoding: str = "utf-8",
) -> bytes:
    """Normalize to bytes."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode(encoding)

def b64_encode(
    data: Union[str, bytes, bytearray, memoryview],
    *,
    urlsafe: bool = False,
    text_encoding: str = "utf-8",
) -> str:
    """Accepts str/bytes/...; returns a base64 string (standard or URL-safe)."""
    raw = _as_bytes(data, encoding=text_encoding)
    fn = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return fn(raw).decode("ascii")

def b64_decode(
    b64_text: str,
    *,
    return_str: bool = False,
    text_encoding: str = "utf-8",
) -> Union[bytes, str]:
    """Decodes either standard or URL-safe b64. Tolerates missing '=' padding."""
    # normalize padding
    missing = len(b64_text) % 4
    if missing:
        b64_text += "=" * (4 - missing)

    try:
        out = base64.b64decode(b64_text, validate=True)     # standard
    except Exception:
        out = base64.urlsafe_b64decode(b64_text)            # url-safe fallback

    if return_str:
        return out.decode(text_encoding)  # may raise UnicodeDecodeError if not text
    return out
