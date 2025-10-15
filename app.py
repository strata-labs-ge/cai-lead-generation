# app.py
# FastAPI WhatsApp Flows data endpoint with strict validation & logging.
# - Decrypts request:  RSA-OAEP(SHA-256) -> 16-byte AES key, AES-GCM -> JSON payload
# - Encrypts response: AES-GCM with same key, returns base64(ciphertext||tag) as text/plain
# - Logs sizes & request metadata so you always see *why* a 400 happens.
#
# Env vars:
#   PRIVATE_KEY_PEM           (required)  -> PKCS#8 private key PEM; may contain \n which will be normalized
#   PRIVATE_KEY_PASSPHRASE    (optional)  -> passphrase for the encrypted PKCS#8
#   FLIP_RESPONSE_IV          (optional)  -> "true"/"false", default false. Flip IV bytes for the response if tester can't decrypt.
#   ALLOW_VARLEN_IV           (optional)  -> "true"/"false", default false. If true, accept 8–16 byte IVs via PyCryptodome.
#
# Run locally (PowerShell):
#   py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1
#   pip install fastapi uvicorn[standard] cryptography
#   # (optional for ALLOW_VARLEN_IV=true)
#   pip install pycryptodome
#   $env:PRIVATE_KEY_PEM = '-----BEGIN ENCRYPTED PRIVATE KEY-----`n...`n-----END ENCRYPTED PRIVATE KEY-----'
#   $env:PRIVATE_KEY_PASSPHRASE = 'yourpass'
#   uvicorn app:app --host 0.0.0.0 --port 8080

import base64
import json
import logging
import os
import time
import uuid
from typing import Tuple

from fastapi import FastAPI, Request, Response, HTTPException

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Configuration ----------

PRIVATE_KEY_PEM = os.environ.get("PRIVATE_KEY_PEM", "")
PRIVATE_KEY_PASSPHRASE = os.environ.get("PRIVATE_KEY_PASSPHRASE", "")
FLIP_RESPONSE_IV = os.environ.get("FLIP_RESPONSE_IV", "false").lower() in ("1", "true", "yes")
ALLOW_VARLEN_IV = os.environ.get("ALLOW_VARLEN_IV", "false").lower() in ("1", "true", "yes")

if not PRIVATE_KEY_PEM:
    raise RuntimeError("PRIVATE_KEY_PEM env var is required")

# Normalize \n if user pasted one-line PEM
if "\\n" in PRIVATE_KEY_PEM:
    PRIVATE_KEY_PEM = PRIVATE_KEY_PEM.replace("\\n", "\n")

try:
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode("utf-8"),
        password=(PRIVATE_KEY_PASSPHRASE.encode("utf-8") if PRIVATE_KEY_PASSPHRASE else None),
    )
except Exception as e:
    raise RuntimeError(f"Failed to load private key: {e}")

# Optional import for variable-length IV mode
AES_varlen = None
if ALLOW_VARLEN_IV:
    try:
        from Crypto.Cipher import AES as _AES  # PyCryptodome
        AES_varlen = _AES
    except Exception as e:
        raise RuntimeError(
            f"ALLOW_VARLEN_IV=true but PyCryptodome isn't available: {e}. "
            f"Install it with: pip install pycryptodome"
        )

# ---------- Logging ----------

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


# ---------- Helpers ----------

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
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        if len(aes_key) != 16:
            raise HTTPException(400, f"Unexpected AES key length {len(aes_key)}; expected 16 bytes.")
        return aes_key
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"RSA decrypt failed: {e}")

def decrypt_payload(aes_key: bytes, iv_b64: str, enc_payload_b64: str, allow_varlen_iv: bool) -> Tuple[dict, bytes, bytes]:
    iv = b64decode_field(iv_b64, "initial_vector")
    enc_blob = b64decode_field(enc_payload_b64, "encrypted_flow_data")

    if len(enc_blob) < 17:
        raise HTTPException(400, "encrypted_flow_data too short.")

    tag = enc_blob[-16:]
    ciphertext = enc_blob[:-16]

    # Standard: 12-byte IV for AES-GCM. If allow_varlen_iv = True, accept 8–16 bytes using PyCryptodome.
    if not allow_varlen_iv:
        if len(iv) != 12:
            raise HTTPException(400, f"AES decrypt failed: IV must be 12 bytes; got {len(iv)}")
        try:
            plaintext = AESGCM(aes_key).decrypt(iv, ciphertext + tag, associated_data=None)
        except Exception as e:
            raise HTTPException(400, f"AES decrypt failed: {e}")
    else:
        if len(iv) < 8 or len(iv) > 16:
            raise HTTPException(400, f"AES decrypt failed: IV must be 8–16 bytes in varlen mode; got {len(iv)}")
        try:
            cipher = AES_varlen.new(aes_key, AES_varlen.MODE_GCM, nonce=iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            raise HTTPException(400, f"AES decrypt failed (varlen): {e}")

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Decrypted payload is not valid JSON")

    return payload, iv, tag  # tag returned only for completeness


def encrypt_response(aes_key: bytes, iv: bytes, response_obj: dict, flip_iv: bool, allow_varlen_iv: bool) -> str:
    resp_iv = iv[::-1] if flip_iv else iv
    plain = json.dumps(response_obj, ensure_ascii=False).encode("utf-8")

    if not allow_varlen_iv:
        # cryptography AESGCM expects 12-byte nonce
        if len(resp_iv) != 12:
            raise HTTPException(500, f"Response IV must be 12 bytes in standard mode; got {len(resp_iv)}")
        blob = AESGCM(aes_key).encrypt(resp_iv, plain, associated_data=None)  # ciphertext||tag
    else:
        if len(resp_iv) < 8 or len(resp_iv) > 16:
            raise HTTPException(500, f"Response IV must be 8–16 bytes in varlen mode; got {len(resp_iv)}")
        cipher = AES_varlen.new(aes_key, AES_varlen.MODE_GCM, nonce=resp_iv)
        ciphertext, tag = cipher.encrypt_and_digest(plain)
        blob = ciphertext + tag

    return base64.b64encode(blob).decode("ascii")


# ---------- Routes ----------

@app.get("/health")
def health():
    return {"ok": True, "flip_response_iv": FLIP_RESPONSE_IV, "allow_varlen_iv": ALLOW_VARLEN_IV}

@app.post("/wa/flow")
async def wa_flow(request: Request):
    request_id = str(uuid.uuid4())[:8]
    t0 = time.time()
    client_ip = request.client.host if request.client else "unknown"

    # Make request_id & client_ip available in log records
    extra = {"request_id": request_id, "client_ip": client_ip}

    # Content-Type check
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

    # Required fields present?
    required = ("encrypted_flow_data", "encrypted_aes_key", "initial_vector")
    missing = [k for k in required if k not in body]
    if missing:
        logger.warning("Missing fields: %s", ",".join(missing), extra=extra)
        raise HTTPException(400, f"Missing required fields: {', '.join(missing)}")

    # Log field sizes to help diagnose wrong IV sizes / tampering
    try:
        iv_dec_len = len(b64decode_field(body["initial_vector"], "initial_vector"))
        enc_dec_len = len(b64decode_field(body["encrypted_flow_data"], "encrypted_flow_data"))
        key_dec_len = len(b64decode_field(body["encrypted_aes_key"], "encrypted_aes_key"))
        logger.info(
            "Req sizes iv=%d enc=%d key=%d allowVarlen=%s flipIV=%s",
            iv_dec_len, enc_dec_len, key_dec_len, ALLOW_VARLEN_IV, FLIP_RESPONSE_IV, extra=extra
        )
    except HTTPException as e:
        logger.warning(f"{e.detail}", extra=extra)
        raise

    # 1) RSA decrypt -> AES key
    aes_key = rsa_oaep_decrypt_aes_key(body["encrypted_aes_key"])

    # 2) AES-GCM decrypt -> payload
    payload, iv, _ = decrypt_payload(aes_key, body["initial_vector"], body["encrypted_flow_data"], ALLOW_VARLEN_IV)

    # ---- Your business logic ----
    action = payload.get("action", "")
    # Build only the fields your Flow UI binds to (replace with your actual keys):
    response_obj = {
        "flow_token": payload.get("flow_token"),
        "echo_action": action,
        # add more fields your Flow references as ${data.*}
    }

    # 3) Encrypt response
    resp_b64 = encrypt_response(aes_key, iv, response_obj, FLIP_RESPONSE_IV, ALLOW_VARLEN_IV)

    dt_ms = int((time.time() - t0) * 1000)
    logger.info("OK action=%s took_ms=%d", action, dt_ms, extra=extra)

    # Must return plain text (base64), not JSON
    return Response(content=resp_b64, media_type="text/plain")
