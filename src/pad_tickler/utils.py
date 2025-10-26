import base64
import importlib.util
import inspect
import types
from typing import Callable, Union, Literal, List

SubmitGuessFn = Callable[[bytes, bytes], bool]

PLUGIN_FUNC_NAME = "submit_guess"

type CiphertextFormat = Union[Literal[
    "b64",
    "b64_urlsafe",
    "hex",
    "raw"
], str]

class PluginLoadError(RuntimeError):
    pass

class PluginSignatureError(TypeError):
    pass


def load_module_from_file(module_file_path: str) -> types.ModuleType:
    """Load a Python module file."""
    spec = importlib.util.spec_from_file_location("guess_fn", module_file_path)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"Could not load spec for: {module_file_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # executes user code
    return mod


def load_guess_fn(module_file_path: str) -> Callable[[bytes, bytes], bool]:
    """Load the user defined guess function from a Python module file."""
    mod = load_module_from_file(module_file_path)
    fn = getattr(mod, PLUGIN_FUNC_NAME, None)
    if fn is None:
        raise PluginLoadError(
            f"Plugin must define `{PLUGIN_FUNC_NAME}(prev_block: bytes, target_block: bytes) -> bool`"
        )

    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    if len(params) != 2 or any(
        p.kind not in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        for p in params
    ):
        raise PluginSignatureError(
            "submit_guess must accept exactly two positional args: (prev_block: bytes, target_block: bytes)"
        )
    return fn


def load_ciphertext(file_path: str, format: CiphertextFormat) -> bytes:
    """Load the ciphertext from a file."""
    with open(file_path, "rb") as f:
        data = f.read()
    if format == "b64":
        return b64_decode(data)
    elif format == "b64_urlsafe":
        return b64_decode(data, urlsafe=True)
    elif format == "hex":
        return bytes.fromhex(data.decode("utf-8"))
    elif format == "raw":
        return data
    else:
        raise ValueError(f"Invalid ciphertext format: {format}")


def _as_bytes(
    data: Union[str, bytes, bytearray, memoryview],
    *,
    encoding: str = "utf-8",
) -> bytes:
    """Normalize values to type bytes."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode(encoding)

def bytestring_from_list_of_blocks(blocks: List[List[bytes]]) -> bytes:
    # Convert list of lists to bytes
    if blocks:
        all_bytes = []
        for byte_list in blocks:
            if byte_list is not None:  # Skip None blocks (like IV)
                all_bytes.extend([b for b in byte_list if b is not None])
        blocks_bytes = bytes(all_bytes)
        return blocks_bytes


def strip_plaintext_padding(plaintext: bytes) -> bytes:
    """ Strip the padding from the plaintext. """
    if not plaintext:
        return plaintext

    tail_value = plaintext[-1]
    if tail_value <= 16:
        return plaintext.rstrip(bytes([tail_value]))

    return plaintext

def b64_encode(
    data: Union[str, bytes, bytearray, memoryview],
    *,
    urlsafe: bool = False,
    text_encoding: str = "utf-8",
) -> str:
    """Accepts str/bytes/etc and return a base64 string (standard or URL-safe)."""
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
        out = base64.b64decode(b64_text, validate=True)
    except Exception:
        out = base64.urlsafe_b64decode(b64_text)  # URL-safe fallback

    if return_str:
        return out.decode(text_encoding)
    return out
