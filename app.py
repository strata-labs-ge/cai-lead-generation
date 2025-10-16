# main.py
import os, json, base64, hmac, hashlib, httpx, uuid
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
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

GRAPH_VERSION = os.environ.get("GRAPH_VERSION", "v24.0")
GRAPH_BASE = f"https://graph.facebook.com/{GRAPH_VERSION}"
WHATSAPP_TOKEN = os.environ.get("WHATSAPP_TOKEN")
WA_PHONE_NUMBER_ID = os.environ.get("WA_PHONE_NUMBER_ID")
FLOW_ID = os.environ.get("CAI_LEAD_INTAKE_FLOW_ID")

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

def normalize_lang(payload_language):
    """
    Accepts either:
    - an object: {"id":"georgian","title":"ქართული"}  (what your Flow sends)
    - or a string id like "georgian"
    Returns the canonical id: english|georgian|russian
    """
    if isinstance(payload_language, dict):
        return (payload_language.get("id") or "").lower()
    if isinstance(payload_language, str):
        return payload_language.lower()
    return "english"

LOCALIZED = {
    "english": {
        "footer_label": "Complete",
        "heading": "Welcome!",
        "body":    "Thanks—your language is set to English."
    },
    "georgian": {
        "footer_label": "დასრულება",
        "heading": "კეთილი იყოს თქვენი მობრძანება!",
        "body":    "გმადლობთ — არჩეული ენაა ქართული."
    },
    "russian": {
        "footer_label": "Готово",
        "heading": "Добро пожаловать!",
        "body":    "Спасибо — выбран русский язык."
    }
}

async def send_flow_message(to_wa_id: str, initial_data: dict | None = None):
    """
    Sends an interactive 'flow' message to the user who typed 'start'.
    `to_wa_id` should be the user's WhatsApp ID from the webhook (value.messages[*].from).
    """
    flow_token = f"start-{uuid.uuid4()}"
    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_id,
        "type": "interactive",
        "interactive": {
            "type": "flow",
            "header": {"type": "text", "text": "Welcome!"},
            "body":   {"text": "Tap below to begin."},
            "footer": {"text": "Powered by your brand"},
            "action": {
                "name": "flow",
                "parameters": {
                    "flow_id": FLOW_ID,
                    "flow_token": flow_token,
                    "flow_action": "navigate",
                    "screen": "WELCOME_SCREEN",
                    # Optional — inject defaults your screen binds via ${data.*}
                    "data": initial_data or { "footer_label": "Complete" }
                }
            }
        }
    }
    url = f"{GRAPH_BASE}/{WA_PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}

    print("[WA SEND PAYLOAD]", payload)
    print("[WA SEND URL]", url)
    print("[WA SEND HEADERS]", headers)
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, headers=headers, json=payload)
        if r.status_code >= 300:
            try:
                print("[WA SEND ERROR]", r.status_code, r.json())
            except Exception:
                print("[WA SEND ERROR RAW]", r.status_code, r.text)
        r.raise_for_status()
    print("[WA SEND SUCCESS]", flow_token)
    return True


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
                        text_body = (msg.get("text") or {}).get("body")
                        # TODO: enqueue for processing, call n8n, etc.
                        print(f"[WA] from={wa_from} text={text_body}")

                        if isinstance(text_body, str) and text_body.strip().lower() in {"start", "/start"}:
                            print(f"[WA] sending flow message to {wa_from}")
                            initial_data = { "footer_label": "Complete" }
                            background_tasks.add_task(send_flow_message, wa_from, initial_data)
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

            selected = (decrypted.get("data") or {}).get("language")
            lang = normalize_lang(selected)
            texts = LOCALIZED.get(lang, LOCALIZED["georgian"])

            response_payload = {
                "screen": "VEHICLE_INTENT", 
                "data": {
                    "heading": texts["heading"],
                    "body": texts["body"],
                    "footer_label": texts["footer_label"]
                }
            }
        else:
            response_payload = {"screen": screen, "data": {"error_message": "Please try again."}}

        encrypted_b64 = encrypt_response(response_payload, aes_key, iv)
        return PlainTextResponse(encrypted_b64, media_type="text/plain")

    except Exception as e:
        print("[FLOW] error:", e)
        return JSONResponse({"error": "server_error"}, status_code=500)
