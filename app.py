# main.py
import os, json, base64, secrets
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def load_private_key():
    pem = os.environ["FLOW_PRIVATE_KEY"].encode("utf-8")
    return serialization.load_pem_private_key(pem, password=None)

def rsa_oaep_decrypt(private_key, encrypted_aes_key_b64: str) -> bytes:
    enc_key = b64d(encrypted_aes_key_b64)
    return private_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def aes_gcm_decrypt(aes_key: bytes, iv_b64: str, ciphertext_b64: str, aad: bytes = None) -> dict:
    iv = b64d(iv_b64)
    ct = b64d(ciphertext_b64)
    aes = AESGCM(aes_key)
    pt = aes.decrypt(iv, ct, aad)
    return json.loads(pt.decode("utf-8"))

def aes_gcm_encrypt(aes_key: bytes, payload: dict, aad: bytes = None):
    iv = secrets.token_bytes(12)  # 12-byte IV for GCM
    aes = AESGCM(aes_key)
    pt = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ct = aes.encrypt(iv, pt, aad)  # returns ciphertext+tag
    return {
        "encrypted_flow_data": b64e(ct),
        "initial_vector": b64e(iv)
    }

@app.post("/whatsapp/flow")
async def whatsapp_flow(request: Request):
    # 1) Parse envelope. Meta sends fields like:
    #    encrypted_aes_key, encrypted_flow_data, initial_vector
    #    Some partners also include action/screen inside decrypted payload.
    envelope = await request.json()
    if os.getenv("FLOW_DEBUG"):
        print("ENVELOPE:", envelope)

    # Health probes / partner pings may be plaintext; short-circuit:
    if isinstance(envelope, dict) and envelope.get("action") == "ping":
        return JSONResponse({"data": {"status": "active"}})

    # 2) Hybrid decrypt
    try:
        priv = load_private_key()
        aes_key = rsa_oaep_decrypt(priv, envelope["encrypted_aes_key"])
        # Optional: AAD if platform provides (often absent).
        aad = None
        req_payload = aes_gcm_decrypt(
            aes_key,
            envelope["initial_vector"],
            envelope["encrypted_flow_data"],
            aad=aad
        )
    except Exception as e:
        # Return a generic 400 so Meta retries w/ backoff
        return JSONResponse({"error": "decrypt_failed"}, status_code=400)

    if os.getenv("FLOW_DEBUG"):
        print("DECRYPTED:", req_payload)

    # 3) Decide route
    action = (req_payload.get("action") or "").upper()
    screen = req_payload.get("screen") or "WELCOME_SCREEN"
    data = req_payload.get("data") or {}
    flow_token = req_payload.get("flow_token")  # echo back in extension_message_response if needed

    # 3a) Health check path:
    # Meta sends a synthetic encrypted request and expects a properly encrypted echo/ack.
    if action == "HEALTH_CHECK":
        resp_payload = {
            "screen": "SUCCESS",
            "data": {"health": "ok"}
        }
    # 3b) First open
    elif action == "INIT":
        resp_payload = {
            "screen": "WELCOME_SCREEN",
            "data": {}
        }
    # 3c) From your Flow's on-click-action name: data_exchange
    elif action == "DATA_EXCHANGE" and screen == "WELCOME_SCREEN":
        # Example: persist or route language preference
        lang_id = data.get("language_id") or data.get("language")
        lang_title = data.get("language_title")
        # Complete the flow and send a follow-up message via extension
        resp_payload = {
            "screen": "SUCCESS",
            "data": {
                "extension_message_response": {
                    "params": {
                        "flow_token": flow_token,
                        "selected_language_id": lang_id,
                        "selected_language_title": lang_title
                    }
                }
            }
        }
    else:
        # Default: stay or recover
        resp_payload = {
            "screen": screen,
            "data": {"error_message": "Please try again."}
        }

    # 4) Encrypt response with a fresh AES-GCM IV; RSA re-wrap the same AES key back to Meta
    try:
        # Re-wrap AES key for response
        # (Many integrations expect you to echo back the same aes_key re-encrypted
        #  with Meta's public key; however, for the Flows data channel, you return
        #  your AES-GCM-encrypted payload and the AES key wrapped with Meta-provided public key on their side.
        #  In practice, Meta expects these three fields present:)
        enc = aes_gcm_encrypt(aes_key, resp_payload, aad=None)

        response_body = {
            "encrypted_aes_key": envelope["encrypted_aes_key"],  # echo back unchanged unless docs specify otherwise
            "encrypted_flow_data": enc["encrypted_flow_data"],
            "initial_vector": enc["initial_vector"]
        }
        # Base64 encode the entire response body
        response_json = json.dumps(response_body, separators=(",", ":"))
        response_b64 = b64e(response_json.encode("utf-8"))
        return JSONResponse(response_b64, headers={"Content-Type": "application/json"})
    except Exception:
        return JSONResponse({"error": "encrypt_failed"}, status_code=500)
