# main.py
import os, json, base64
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

app = FastAPI()

# Load the private key string
PRIVATE_KEY = os.environ.get('FLOW_PRIVATE_KEY')

def decrypt_request(encrypted_flow_data_b64, encrypted_aes_key_b64, initial_vector_b64):
    flow_data = base64.b64decode(encrypted_flow_data_b64)
    iv = base64.b64decode(initial_vector_b64)

    # Decrypt the AES encryption key
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY.encode('utf-8'), password=None)
    aes_key = private_key.decrypt(encrypted_aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), 
        algorithm=hashes.SHA256(), 
        label=None))

    # Decrypt the Flow data
    encrypted_flow_data_body = flow_data[:-16]
    encrypted_flow_data_tag = flow_data[-16:]
    decryptor = Cipher(algorithms.AES(aes_key),
                       modes.GCM(iv, encrypted_flow_data_tag)).decryptor()
    decrypted_data_bytes = decryptor.update(
        encrypted_flow_data_body) + decryptor.finalize()
    decrypted_data = json.loads(decrypted_data_bytes.decode("utf-8"))
    return decrypted_data, aes_key, iv

def encrypt_response(response, aes_key, iv):
    # Flip the initialization vector
    flipped_iv = bytearray()
    for byte in iv:
        flipped_iv.append(byte ^ 0xFF)

    # Encrypt the response data
    encryptor = Cipher(algorithms.AES(aes_key),
                       modes.GCM(flipped_iv)).encryptor()
    return base64.b64encode(
        encryptor.update(json.dumps(response).encode("utf-8")) +
        encryptor.finalize() +
        encryptor.tag
    ).decode("utf-8")

@app.post("/whatsapp/flow")
async def whatsapp_flow(request: Request):
    try:
        # Parse the request body
        body = await request.json()

        # Read the request fields
        encrypted_flow_data_b64 = body['encrypted_flow_data']
        encrypted_aes_key_b64 = body['encrypted_aes_key']
        initial_vector_b64 = body['initial_vector']

        decrypted_data, aes_key, iv = decrypt_request(
            encrypted_flow_data_b64, encrypted_aes_key_b64, initial_vector_b64)
        
        if os.getenv("FLOW_DEBUG"):
            print("DECRYPTED:", decrypted_data)

        # Health probes / partner pings may be plaintext; short-circuit:
        if isinstance(decrypted_data, dict) and decrypted_data.get("action") == "ping":
            return JSONResponse({"data": {"status": "active"}})

        # Decide route
        action = (decrypted_data.get("action") or "").upper()
        screen = decrypted_data.get("screen") or "WELCOME_SCREEN"
        data = decrypted_data.get("data") or {}
        flow_token = decrypted_data.get("flow_token")  # echo back in extension_message_response if needed

        # Health check path:
        # Meta sends a synthetic encrypted request and expects a properly encrypted echo/ack.
        if action == "HEALTH_CHECK":
            response = {
                "screen": "SUCCESS",
                "data": {"health": "ok"}
            }
        # First open
        elif action == "INIT":
            response = {
                "screen": "WELCOME_SCREEN",
                "data": {}
            }
        # From your Flow's on-click-action name: data_exchange
        elif action == "DATA_EXCHANGE" and screen == "WELCOME_SCREEN":
            # Example: persist or route language preference
            lang_id = data.get("language_id") or data.get("language")
            lang_title = data.get("language_title")
            # Complete the flow and send a follow-up message via extension
            response = {
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
            response = {
                "screen": screen,
                "data": {"error_message": "Please try again."}
            }

        # Return the response as Base64 encoded plaintext (matching Django implementation)
        return JSONResponse(encrypt_response(response, aes_key, iv), headers={"Content-Type": "text/plain"})
    except Exception as e:
        if os.getenv("FLOW_DEBUG"):
            print("ERROR:", e)
        return JSONResponse({"error": "processing_failed"}, status_code=500)
