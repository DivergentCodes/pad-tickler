import base64
import requests
import time


def submit_guess(prev_block: bytes, target_block: bytes) -> bool:
    """ Submit a padding guess to the oracle (demo API) to validate the given ciphertext. """
    ciphertext = prev_block + target_block
    ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")

    payload = {
        "alg": "AES-128-CBC",
        "ciphertext_b64": ciphertext_b64
    }

    try:
        url = "http://127.0.0.1:8000/api/validate"
        response = requests.post(url, json=payload, timeout=10)
        time.sleep(0.01)  # Small delay to prevent overwhelming the server
        return response.status_code == 200
    except Exception as e:
        print(f"Request failed: {e}")
        return False

