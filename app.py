import base64, json, os
from fastapi import FastAPI, Request, Response, HTTPException
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Config via env vars ----
PRIVATE_KEY_PEM = os.environ.get("PRIVATE_KEY_PEM", "")
PRIVATE_KEY_PASSPHRASE = os.environ.get("PRIVATE_KEY_PASSPHRASE", "")
FLIP_RESPONSE_IV = os.environ.get("FLIP_RESPONSE_IV", "false").lower() in ("1","true","yes")

if not PRIVATE_KEY_PEM:
    raise RuntimeError("PRIVATE_KEY_PEM env var is required")
if "\\n" in PRIVATE_KEY_PEM:
    PRIVATE_KEY_PEM = PRIVATE_KEY_PEM.replace("\\n", "\n")

private_key = serialization.load_pem_private_key(
    PRIVATE_KEY_PEM.encode("utf-8"),
    password=(PRIVATE_KEY_PASSPHRASE.encode("utf-8") if PRIVATE_KEY_PASSPHRASE else None),
)

app = FastAPI()

@app.get("/health")
def health(): return {"ok": True}

@app.post("/wa/flow")
async def wa_flow(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    req_keys = ("encrypted_flow_data","encrypted_aes_key","initial_vector")
    if any(k not in body for k in req_keys):
        raise HTTPException(400, f"Missing required fields: {req_keys}")

    try:
        # 1) RSA-OAEP(SHA-256) → 16-byte AES key
        aes_key = private_key.decrypt(
            base64.b64decode(body["encrypted_aes_key"]),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        if len(aes_key) != 16: raise ValueError(f"AES key must be 16 bytes; got {len(aes_key)}")
    except Exception as e:
        raise HTTPException(400, f"RSA decrypt failed: {e}")

    try:
        iv = base64.b64decode(body["initial_vector"])
        if len(iv) != 12: raise ValueError(f"IV must be 12 bytes; got {len(iv)}")

        blob = base64.b64decode(body["encrypted_flow_data"])
        ciphertext, tag = blob[:-16], blob[-16:]
        plaintext = AESGCM(aes_key).decrypt(iv, ciphertext + tag, None)
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise HTTPException(400, f"AES decrypt failed: {e}")

    # ---- Your logic (return only what your Flow binds to) ----
    response_obj = {
        "flow_token": payload.get("flow_token"),
        "echo_action": payload.get("action"),
        # put whatever ${data.*} your screens expect here
    }

    try:
        resp_iv = iv[::-1] if FLIP_RESPONSE_IV else iv  # toggle if tester can't decrypt response
        resp_plain = json.dumps(response_obj, ensure_ascii=False).encode("utf-8")
        resp_blob = AESGCM(aes_key).encrypt(resp_iv, resp_plain, None)  # ciphertext||tag
        resp_b64 = base64.b64encode(resp_blob).decode("ascii")
    except Exception as e:
        raise HTTPException(500, f"AES encrypt failed: {e}")

    return Response(content=resp_b64, media_type="text/plain")