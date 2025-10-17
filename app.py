# main.py
import os, json, base64, hmac, hashlib, uuid, logging
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import PlainTextResponse, JSONResponse
import httpx

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

app = FastAPI()

# Log every request path + status
@app.middleware("http")
async def log_requests(request: Request, call_next):
    log.info("-> %s %s", request.method, request.url.path)
    resp = await call_next(request)
    log.info("<- %s %s %s", request.method, request.url.path, resp.status_code)
    return resp

# ---------- Environment ----------
PRIVATE_KEY_PEM   = os.environ["PRIVATE_KEY"]                # full PEM including headers
VERIFY_TOKEN      = os.environ.get("FB_VERIFY_TOKEN", "")
APP_SECRET        = os.environ.get("FB_APP_SECRET", "")

GRAPH_VERSION     = os.environ.get("GRAPH_VERSION", "v22.0")
GRAPH_BASE        = f"https://graph.facebook.com/{GRAPH_VERSION}"
WHATSAPP_TOKEN    = os.environ.get("WHATSAPP_TOKEN")
WA_PHONE_NUMBER_ID= os.environ.get("WA_PHONE_NUMBER_ID")
FLOW_ID           = os.environ.get("CAI_LEAD_INTAKE_FLOW_ID")

# ---------- Flow crypto helpers ----------
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

# ---------- Webhooks signature helper ----------
def verify_signature(app_secret: str, raw_body: bytes, header_sig: str) -> bool:
    # header format: "sha256=<hex>"
    if not app_secret:
        log.warning("FB_APP_SECRET missing; cannot verify signature.")
        return False
    if not header_sig or not header_sig.startswith("sha256="):
        log.warning("Missing/invalid X-Hub-Signature-256 header: %r", header_sig)
        return False
    their_sig_hex = header_sig.split("=", 1)[1]
    ours_hex = hmac.new(app_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    ok = hmac.compare_digest(ours_hex, their_sig_hex)
    if not ok:
        log.warning("Signature mismatch. ours=%s theirs=%s", ours_hex, their_sig_hex)
    return ok

# ---------- Language helpers ----------
def normalize_lang(payload_language):
    if isinstance(payload_language, dict):
        return (payload_language.get("id") or "").lower()
    if isinstance(payload_language, str):
        return payload_language.lower()
    return "english"

LOCALIZED = {
    "english":  {"footer_label": "Complete", "heading": "Welcome!"},
    "georgian": {"footer_label": "დასრულება", "heading": "კეთილი იყოს თქვენი მობრძანება!",  "vehicle_types": [{"id": "sedan", "title": "სედანი"}, {"id": "suv", "title": "ჯიპი"}, {"id": "coupe_convertible", "title": "კუპე / კაბრიოლეტი"}, {"id": "pickup", "title": "პიკაპი"}, {"id": "electric_hybrid", "title": "ელექტრო / ჰიბრიდი"}]},
    "russian":  {"footer_label": "Готово", "heading": "Добро пожаловать!"}
}

# ---------- Sender: interactive Flow CTA ----------
async def send_flow_message(to_wa_id: str, initial_data: dict | None = None):
    if not (WHATSAPP_TOKEN and WA_PHONE_NUMBER_ID and FLOW_ID):
        log.error("Missing env vars: WHATSAPP_TOKEN=%s PNID=%s FLOW_ID=%s",
                  bool(WHATSAPP_TOKEN), bool(WA_PHONE_NUMBER_ID), bool(FLOW_ID))
        return False

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
                    "flow_message_version": "3",
                    "flow_id": FLOW_ID,
                    "flow_token": flow_token,
                    "flow_cta": "Open",
                    "flow_action": "navigate",
                    "flow_action_payload": {
                        "screen": "WELCOME_SCREEN",
                        "data": initial_data or {"footer_label": "Complete"}
                    }
                }
            }
        }
    }
    url = f"{GRAPH_BASE}/{WA_PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}

    log.info("[SEND] POST %s to=%s payload=%s", url, to_wa_id, json.dumps(payload, ensure_ascii=False))
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(url, headers=headers, json=payload)
            ct = r.headers.get("content-type", "")
            body = r.text if "application/json" not in ct else r.json()
            if r.status_code >= 300:
                log.error("[SEND ERROR] %s %s", r.status_code, body)
            else:
                log.info("[SEND OK] %s %s", r.status_code, body)
            r.raise_for_status()
        return True
    except Exception as e:
        log.exception("[SEND EXC] %s", e)
        return False

# ---------- Health ----------
@app.get("/healthz")
async def healthz():
    log.info("Health check hit")
    return {"ok": True}

# ---------- WEBHOOKS (Graph API) ----------
@app.get("/whatsapp/webhook")
async def whatsapp_webhook_verify(request: Request):
    params = request.query_params
    log.info("Webhook VERIFY params: %s", dict(params))
    mode = params.get("hub.mode")
    token = params.get("hub.verify_token")
    challenge = params.get("hub.challenge")
    if mode == "subscribe" and token and token == VERIFY_TOKEN and challenge:
        return PlainTextResponse(challenge, status_code=200)
    log.warning("Webhook verify failed: mode=%s token_match=%s", mode, token == VERIFY_TOKEN)
    return PlainTextResponse("Forbidden", status_code=403)

@app.post("/whatsapp/webhook")
async def whatsapp_webhook_receive(request: Request, background_tasks: BackgroundTasks):
    raw = await request.body()
    log.info("Webhook POST headers: %s", dict(request.headers))

    if not verify_signature(APP_SECRET, raw, request.headers.get("X-Hub-Signature-256")):
        # Log minimal body to avoid PII (expand if needed)
        log.warning("Rejecting POST with invalid signature. Body len=%d", len(raw or b""))
        raise HTTPException(status_code=403, detail="Invalid signature")

    try:
        payload = json.loads(raw.decode("utf-8"))
        log.info("Webhook payload: %s", json.dumps(payload, ensure_ascii=False))
    except Exception:
        log.exception("JSON decode failed")
        return JSONResponse({"status": "bad json"}, status_code=400)

    try:
        if payload.get("object") == "whatsapp_business_account":
            for entry in payload.get("entry", []):
                for change in entry.get("changes", []):
                    value = change.get("value", {})
                    for msg in value.get("messages", []) or []:
                        wa_from = msg.get("from")
                        text_body = (msg.get("text") or {}).get("body", "")
                        log.info("Inbound msg from=%s body=%r", wa_from, text_body)
                        if isinstance(text_body, str) and text_body.strip().lower() in {"start", "/start"}:
                            background_tasks.add_task(send_flow_message, wa_from, {
                                "footer_label": "Complete",
                                "languages": [
                                    {"id":"english","title":"English"},
                                    {"id":"georgian","title":"ქართული"},
                                    {"id":"russian","title":"Русский"}
                                ]
                            })
                            log.info("Queued Flow send for %s", wa_from)
    except Exception:
        log.exception("Webhook routing error")

    return JSONResponse({"status": "ok"}, status_code=200)

# ---------- FLOWS DATA CHANNEL ----------
@app.post("/whatsapp/flow")
async def whatsapp_flow(request: Request):
    try:
        body = await request.json()
        # Encrypted envelope
        enc_flow = body["encrypted_flow_data"]
        enc_key  = body["encrypted_aes_key"]
        iv_b64   = body["initial_vector"]

        decrypted, aes_key, iv = decrypt_request(enc_flow, enc_key, iv_b64)
        log.info("[FLOW] decrypted: %s", json.dumps(decrypted, ensure_ascii=False))

        action = (decrypted.get("action") or "").upper()
        screen = decrypted.get("screen") or "WELCOME_SCREEN"
        data   = decrypted.get("data") or {}

        print(action, screen, data)
        LANG_TO_SCREEN = {
            "english":  "VEHICLE_INTENT_EN",
            "georgian": "VEHICLE_INTENT_GE",
            "russian":  "VEHICLE_INTENT_RU"
        }

        if action in {"PING", "HEALTH_CHECK"}:
            response_payload = {"data": {"status": "active"}}
        elif action == "INIT":
            response_payload = {"screen": "WELCOME_SCREEN", "data": {"footer_label": LOCALIZED["english"]["footer_label"]}}
        elif action == "DATA_EXCHANGE" and screen == "WELCOME_SCREEN":
            selected = (decrypted.get("data") or {}).get("language")
            lang = normalize_lang(selected)
            texts = LOCALIZED.get(lang, LOCALIZED["georgian"])
            print(texts)
            # NOTE: ensure this screen exists in your Flow routing model
            next_screen = LANG_TO_SCREEN.get(lang, "VEHICLE_INTENT_GE")  # or "SECOND_SCREEN_EN/KA/RU" if that's what you defined
            response_payload = {
                "screen": next_screen,
                "data": {
                    "vehicle_types": [
                        {"id": "sedan", "title": texts["vehicle_types"][0]["title"]},
                        {"id": "suv", "title": texts["vehicle_types"][1]["title"]},
                        {"id": "coupe_convertible", "title": texts["vehicle_types"][2]["title"]},
                        {"id": "pickup", "title": texts["vehicle_types"][3]["title"]},
                        {"id": "electric_hybrid", "title": texts["vehicle_types"][4]["title"]}
                    ],
                    "footer_label": texts["footer_label"]
                }
            }
            print(response_payload)
        elif action == "DATA_EXCHANGE" and screen == "VEHICLE_INTENT_GE":
            selected = (decrypted.get("data") or {}).get("vehicle_type")
            print(selected)
            # vehicle_type = selected.get("id")
            # vehicle_type_title = selected.get("title")
            next_screen = "BUDGET_RANGE_GE"
            response_payload = {
                "screen": next_screen,
                "data": {
                    "budget_ranges": [
                        {"id":"under_ten_thousand","title":"$10,000-ზე ნაკლები"},
                        {"id":"ten_thousand_twenty","title":"$10,000-დან $20,000-მდე"},
                        {"id":"twenty_thousand_thirty","title":"$20,000-დან $30,000-მდე"},
                        {"id":"over_thirty_thousand","title":"$30,000-ზე მეტი"}
                    ]
                }
            }
            print(response_payload)
        elif action == "DATA_EXCHANGE" and screen == "BUDGET_RANGE_GE":
            selected = (decrypted.get("data") or {}).get("budget_range")
            print(selected)
            # budget_range = selected.get("id")
            # budget_range_title = selected.get("title")
            next_screen = "PRIORITY_PREFS_GE"
            response_payload = {
                "screen": next_screen,
                "data": {
                    "priority_prefs": [
                        {"id":"lowest_price","title":"დაბალი ფასი"},
                        {"id":"fast_delivery","title":"სწრაფი მიწოდება"},
                        {"id":"newer_model","title":"ახალი მოდელები"},
                        {"id":"minimal_damage","title":"მინიმალური დაზიანება"}
                    ]
                }
            }
            print(response_payload)
        elif action == "DATA_EXCHANGE" and screen == "PRIORITY_PREFS_GE":
            next_screen = "LEAD_QUALIFICATION_GE"
            response_payload = {
                "screen": next_screen,
                "data": {
                    "opt_in": [
                        {"id":"yes_call","title":"დიახ, დამირეკეთ"},
                        {"id":"send_wa_quote","title":"WhatsApp-ში მომწერეთ"},
                        {"id":"not_now","title":"ახლა არა"}
                    ]
                }
            }
            print(response_payload)
        else:
            response_payload = {"screen": screen, "data": {"error_message": "Please try again."}}

        encrypted_b64 = encrypt_response(response_payload, aes_key, iv)
        return PlainTextResponse(encrypted_b64, media_type="text/plain")

    except Exception as e:
        log.exception("[FLOW] error: %s", e)
        return JSONResponse({"error": "server_error"}, status_code=500)
