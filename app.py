# main.py
import os, json, base64
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI()

# Set this on Render → Environment
# PRIVATE_KEY must include the full PEM header/footer
PRIVATE_KEY_PEM = os.environ["PRIVATE_KEY"]

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
    # 3) Flip the IV for the response (XOR each byte with 0xFF) per Meta guide
    flipped_iv = bytes((b ^ 0xFF) for b in iv)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(flipped_iv)).encryptor()
    ct = encryptor.update(json.dumps(payload, separators=(",", ":")).encode("utf-8")) + encryptor.finalize()
    # Return Base64 of (ciphertext + tag)
    return b64e(ct + encryptor.tag)

@app.post("/whatsapp/flow")
async def whatsapp_flow(request: Request):
    try:
        body = await request.json()

        # Health probes may sometimes come differently; handle the standard encrypted envelope:
        enc_flow = body["encrypted_flow_data"]
        enc_key = body["encrypted_aes_key"]
        iv_b64 = body["initial_vector"]

        decrypted, aes_key, iv = decrypt_request(enc_flow, enc_key, iv_b64)
        # `decrypted` typically has: action, screen, data, flow_token, etc.
        print(decrypted)

        action = (decrypted.get("action") or "").upper()
        screen = decrypted.get("screen") or "WELCOME_SCREEN"
        data   = decrypted.get("data") or {}

        # Minimal router (adjust to your flow):
        if action == "PING":
            response_payload = {"data": {"status": "active"}}
        elif action == "INIT":
            response_payload = {"screen": "WELCOME_SCREEN", "data": {}}
        elif action == "DATA_EXCHANGE" and screen == "WELCOME_SCREEN":
            # Example: echo selection and finish
            response_payload = {"screen": "SUCCESS", "data": {"ok": True}}
        else:
            response_payload = {"screen": screen, "data": {"error_message": "Please try again."}}

        # IMPORTANT: return base64 ciphertext+tag as text/plain
        encrypted_b64 = encrypt_response(response_payload, aes_key, iv)
        return PlainTextResponse(encrypted_b64, media_type="text/plain")
    except Exception as e:
        # Returning JSON 500 is fine for debugging; Meta will retry health checks
        return JSONResponse({"error": "server_error"}, status_code=500)
