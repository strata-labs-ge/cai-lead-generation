# main.py
import os, json, base64, hmac, hashlib
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI()

# === Environment ===
PRIVATE_KEY_PEM = os.environ["PRIVATE_KEY"]             # full PEM including headers
VERIFY_TOKEN     = os.environ.get("FB_VERIFY_TOKEN", "")  # your chosen verify token
APP_SECRET       = os.environ.get("FB_APP_SECRET", "")    # from Meta App → Basic

# === Helpers (Flow crypto) ===
def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def decrypt_request(encrypted_flow_data_b64: str, encrypted_aes_key_b64: str, iv_b64: str):
    flow_data = b64d(encrypted_flow_data_b64)
    iv = b64d(iv_b64)

    # 1) Decrypt AES key via RSA-OAEP(SHA-256)
    enc_aes_key = b64d(encrypted_aes_key_b64)
    private_key = load_pem_private_key(PRIVATE_KEY_PEM.encode("utf-8"), password=None)
    aes_key = private_key.decrypt(
        enc_aes_key,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    # 2) AES-GCM decrypt: last 16 bytes are the tag
    ct, tag = flow_data[:-16], flow_data[-16:]
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
    plaintext = decryptor.update(ct) + decryptor.finalize()
    return json.loads(plaintext.decode("utf-8")), aes_key, iv

def encrypt_response(payload: dict, aes_key: bytes, iv: bytes) -> str:
    # Flip the IV for the response (XOR each byte with 0xFF) per Meta guide
    flipped_iv = bytes((b ^ 0xFF) for b in iv)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(flipped_iv)).encryptor()
    ct = encryptor.update(json.dumps(payload, separators=(",", ":")).encode("utf-8")) + encryptor.finalize()
    # Return Base64 of (ciphertext + tag)
    return b64e(ct + encryptor.tag)

# === Helpers (Webhooks signature) ===
def verify_signature(app_secret: str, raw_body: bytes, header_sig: str) -> bool:
    # header format: "sha256=<hex>"
    if not header_sig or not header_sig.startswith("sha256=") or not app_secret:
        return False
    their_sig_hex = header_sig.split("=", 1)[1]
    ours_hex = hmac.new(app_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(ours_hex, their_sig_hex)

# ========== WEBHOOKS (Graph API) ==========
@app.get("/whatsapp/webhook")
async def whatsapp_webhook_verify(request: Request):
    # Meta calls: ?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    params = request.query_params
    mode = params.get("hub.mode")
    token = params.get("hub.verify_token")
    challenge = params.get("hub.challenge")
    if mode == "subscribe" and token and token == VERIFY_TOKEN and challenge:
        return PlainTextResponse(challenge, status_code=200)
    return PlainTextResponse("Forbidden", status_code=403)

@app.post("/whatsapp/webhook")
async def whatsapp_webhook_receive(request: Request):
    # Verify X-Hub-Signature-256 against RAW body
    raw = await request.body()
    header_sig = request.headers.get("X-Hub-Signature-256")
    if not verify_signature(APP_SECRET, raw, header_sig):
        raise HTTPException(status_code=403, detail="Invalid signature")

    # Parse JSON AFTER signature check
    payload = json.loads(raw.decode("utf-8"))
    print(payload)

    # --- Optional: route WhatsApp messages quickly (keep it FAST) ---
    # WhatsApp Cloud API typically posts: { "object":"whatsapp_business_account", "entry":[ ... ] }
    try:
        if payload.get("object") == "whatsapp_business_account":
            for entry in payload.get("entry", []):
                for change in entry.get("changes", []):
                    value = change.get("value", {})
                    # Messages array when a message arrives
                    for msg in value.get("messages", []) or []:
                        wa_from = msg.get("from")
                        text = (msg.get("text") or {}).get("body")
                        # TODO: enqueue for processing, call n8n, etc.
                        print(f"[WA] from={wa_from} text={text}")
    except Exception:
        # swallow routing errors; don’t block 200 ack
        pass

    # Always ack quickly
    return JSONResponse({"status": "ok"}, status_code=200)

# ========== FLOWS DATA CHANNEL ==========
@app.post("/whatsapp/flow")
async def whatsapp_flow(request: Request):
    try:
        body = await request.json()

        # Encrypted envelope
        enc_flow = body["encrypted_flow_data"]
        enc_key  = body["encrypted_aes_key"]
        iv_b64   = body["initial_vector"]

        decrypted, aes_key, iv = decrypt_request(enc_flow, enc_key, iv_b64)
        print("[FLOW] decrypted:", decrypted)

        action = (decrypted.get("action") or "").upper()
        screen = decrypted.get("screen") or "WELCOME_SCREEN"
        data   = decrypted.get("data") or {}

        if action == "PING" or action == "HEALTH_CHECK":
            response_payload = {"data": {"status": "active"}}
        elif action == "INIT":
            response_payload = {"screen": "WELCOME_SCREEN", "data": {}}
        elif action == "DATA_EXCHANGE" and screen == "WELCOME_SCREEN":
            # Example: echo selection and finish
            print("[FLOW] data_exchange data:", data)
            response_payload = {"screen": "SUCCESS", "data": {"ok": True}}
        else:
            response_payload = {"screen": screen, "data": {"error_message": "Please try again."}}

        encrypted_b64 = encrypt_response(response_payload, aes_key, iv)
        return PlainTextResponse(encrypted_b64, media_type="text/plain")

    except Exception as e:
        print("[FLOW] error:", e)
        return JSONResponse({"error": "server_error"}, status_code=500)
