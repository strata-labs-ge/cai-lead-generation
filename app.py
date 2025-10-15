# app.py
import base64
import json
import logging
import os
import time
import uuid
from typing import Tuple

from fastapi import FastAPI, Request, Response, HTTPException

# crypto (standard)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------- Env / config ----------------

PRIVATE_KEY_PEM = os.environ.get("PRIVATE_KEY_PEM", "")
PRIVATE_KEY_PASSPHRASE = os.environ.get("PRIVATE_KEY_PASSPHRASE", "")
FLIP_RESPONSE_IV = os.environ.get("FLIP_RESPONSE_IV", "false").lower() in ("1", "true", "yes")
ALLOW_VARLEN_IV = os.environ.get("ALLOW_VARLEN_IV", "false").lower() in ("1", "true", "yes")

if not PRIVATE_KEY_PEM:
    raise RuntimeError("PRIVATE_KEY_PEM env var is required")

# normalize \n if pasted on one line
if "\\n" in PRIVATE_KEY_PEM:
    PRIVATE_KEY_PEM = PRIVATE_KEY_PEM.replace("\\n", "\n")

try:
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode("utf-8"),
        password=(PRIVATE_KEY_PASSPHRASE.encode("utf-8") if PRIVATE_KEY_PASSPHRASE else None),
    )
except Exception as e:
    raise RuntimeError(f"Failed to load private key: {e}")

AES_varlen = None
if ALLOW_VARLEN_IV:
    try:
        from Crypto.Cipher import AES as _AES  # PyCryptodome
        AES_varlen = _AES
    except Exception as e:
        raise RuntimeError("ALLOW_VARLEN_IV=true requires pycryptodome. pip install pycryptodome") from e

# ---------------- Logging ----------------

logger = logging.getLogger("wa_flows")
handler = logging.StreamHandler()
formatter = logging.Formatter(
    fmt="%(asctime)s %(levelname)s req=%(request_id)s ip=%(client_ip)s msg=%(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

app = FastAPI()


# ---------------- Helpers ----------------

def b64decode_field(b64_str: str, field: str) -> bytes:
    try:
        return base64.b64decode(b64_str, validate=True)
    except Exception as e:
        raise HTTPException(400, f"Base64 decode error in '{field}': {e}")

def rsa_oaep_decrypt_aes_key(enc_key_b64: str) -> bytes:
    try:
        enc_key = b64decode_field(enc_key_b64, "encrypted_aes_key")
        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        if len(aes_key) != 16:
            raise HTTPException(400, f"Unexpected AES key length {len(aes_key)}; expected 16 bytes.")
        return aes_key
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"RSA decrypt failed: {e}")

def decrypt_payload(aes_key: bytes, iv_b64: str, enc_payload_b64: str) -> Tuple[dict, bytes]:
    iv = b64decode_field(iv_b64, "initial_vector")
    blob = b64decode_field(enc_payload_b64, "encrypted_flow_data")
    if len(blob) < 17:
        raise HTTPException(400, "encrypted_flow_data too short")

    ciphertext, tag = blob[:-16], blob[-16:]

    if not ALLOW_VARLEN_IV:
        if len(iv) != 12:
            raise HTTPException(400, f"AES decrypt failed: IV must be 12 bytes; got {len(iv)}")
        try:
            plaintext = AESGCM(aes_key).decrypt(iv, ciphertext + tag, associated_data=None)
        except Exception as e:
            raise HTTPException(400, f"AES decrypt failed: {e}")
    else:
        if not (8 <= len(iv) <= 16):
            raise HTTPException(400, f"AES decrypt failed: IV must be 8–16 bytes; got {len(iv)}")
        try:
            cipher = AES_varlen.new(aes_key, AES_varlen.MODE_GCM, nonce=iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            raise HTTPException(400, f"AES decrypt failed (varlen): {e}")

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Decrypted payload is not valid JSON")

    return payload, iv

def encrypt_response(aes_key: bytes, iv: bytes, response_obj: dict) -> Tuple[str, bytes]:
    resp_iv = iv[::-1] if FLIP_RESPONSE_IV else iv
    plain = json.dumps(response_obj, ensure_ascii=False).encode("utf-8")

    if not ALLOW_VARLEN_IV:
        if len(resp_iv) != 12:
            raise HTTPException(500, f"Response IV must be 12 bytes in standard mode; got {len(resp_iv)}")
        blob = AESGCM(aes_key).encrypt(resp_iv, plain, associated_data=None)  # ciphertext||tag
    else:
        if not (8 <= len(resp_iv) <= 16):
            raise HTTPException(500, f"Response IV must be 8–16 bytes; got {len(resp_iv)}")
        cipher = AES_varlen.new(aes_key, AES_varlen.MODE_GCM, nonce=resp_iv)
        ciphertext, tag = cipher.encrypt_and_digest(plain)
        blob = ciphertext + tag

    resp_b64 = base64.b64encode(blob).decode("ascii")
    return resp_b64, resp_iv


# ---------------- Routes ----------------

@app.get("/health")
def health():
    return {
        "ok": True,
        "flip_response_iv": FLIP_RESPONSE_IV,
        "allow_varlen_iv": ALLOW_VARLEN_IV,
    }

@app.post("/wa/flow")
async def wa_flow(request: Request):
    req_id = str(uuid.uuid4())[:8]
    t0 = time.time()
    client_ip = request.client.host if request.client else "unknown"
    extra = {"request_id": req_id, "client_ip": client_ip}

    ct = request.headers.get("content-type", "")
    if "application/json" not in ct.lower():
        logger.warning("Bad content-type: %s", ct, extra=extra)
        raise HTTPException(400, f"Expected Content-Type: application/json, got: {ct or 'none'}")

    raw = await request.body()
    if not raw:
        logger.warning("Empty body", extra=extra)
        raise HTTPException(400, "Empty body")

    try:
        body = json.loads(raw)
    except Exception:
        logger.warning("Invalid JSON", extra=extra)
        raise HTTPException(400, "Invalid JSON")

    # presence check
    required = ("encrypted_flow_data", "encrypted_aes_key", "initial_vector")
    missing = [k for k in required if k not in body]
    if missing:
        logger.warning("Missing fields: %s", ",".join(missing), extra=extra)
        raise HTTPException(400, f"Missing required fields: {', '.join(missing)}")

    # helpful size logs
    try:
        iv_len = len(b64decode_field(body["initial_vector"], "initial_vector"))
        enc_len = len(b64decode_field(body["encrypted_flow_data"], "encrypted_flow_data"))
        key_len = len(b64decode_field(body["encrypted_aes_key"], "encrypted_aes_key"))
        logger.info(
            "Req sizes iv=%d enc=%d key=%d allowVarlen=%s flipIV=%s",
            iv_len, enc_len, key_len, ALLOW_VARLEN_IV, FLIP_RESPONSE_IV, extra=extra
        )
    except HTTPException as e:
        logger.warning(e.detail, extra=extra)
        raise

    # 1) RSA → AES key
    aes_key = rsa_oaep_decrypt_aes_key(body["encrypted_aes_key"])

    # 2) AES-GCM → payload
    payload, iv = decrypt_payload(aes_key, body["initial_vector"], body["encrypted_flow_data"])

    # ---- Your logic (minimal safe default) ----
    action = payload.get("action", "")
    response_obj = {
        # include flow_token to be friendly (not strictly required by health-check)
        "flow_token": payload.get("flow_token"),
        "echo_action": action or "ping",
    }

    # 3) Encrypt response
    resp_b64, resp_iv = encrypt_response(aes_key, iv, response_obj)

    dt_ms = int((time.time() - t0) * 1000)
    # Log response diagnostics (length & short prefix only)
    logger.info(
        "OK action=%s took_ms=%d resp_iv=%d out_b64=%d prefix=%s",
        action, dt_ms, len(resp_iv), len(resp_b64), resp_b64[:16], extra=extra
    )

    # IMPORTANT: return plain text (no quotes, no JSON)
    return Response(content=resp_b64, media_type="text/plain")
