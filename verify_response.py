# verify_response.py
# Decrypts your endpoint's Base64 response using the request's encrypted_aes_key + initial_vector.

import base64, json, os, argparse, sys

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Optional var-length IV (8–16 bytes)
USE_VARLEN = os.environ.get("ALLOW_VARLEN_IV", "false").lower() in ("1","true","yes")
try:
    if USE_VARLEN:
        from Crypto.Cipher import AES as AES_varlen  # pycryptodome
except Exception:
    AES_varlen = None

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64d(x, name):
    try:
        return base64.b64decode(x, validate=True)
    except Exception as e:
        print(f"[!] bad base64 in {name}: {e}", file=sys.stderr)
        sys.exit(2)

def main():
    ap = argparse.ArgumentParser(description="Verify WhatsApp Flows response decryption")
    ap.add_argument("--private-key", required=True, help="path to PKCS#8 private key PEM")
    ap.add_argument("--passphrase", default="", help="passphrase if key is encrypted")
    ap.add_argument("--initial-vector", required=True, help="base64 IV from request")
    ap.add_argument("--encrypted-aes-key", required=True, help="base64 RSA-OAEP from request")
    ap.add_argument("--response-b64", required=True, help="base64 ciphertext||tag returned by your endpoint")
    ap.add_argument("--flip-iv", action="store_true", help="set if server flips IV for response")
    args = ap.parse_args()

    # Load private key
    with open(args.private_key, "rb") as f:
        pem = f.read()
    try:
        key = serialization.load_pem_private_key(
            pem, password=(args.passphrase.encode() if args.passphrase else None)
        )
    except Exception as e:
        print(f"[!] failed to load private key: {e}", file=sys.stderr)
        sys.exit(2)

    # Decrypt AES key
    aes_key = key.decrypt(
        b64d(args.encrypted_aes_key, "encrypted_aes_key"),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    if len(aes_key) != 16:
        print(f"[!] AES key length must be 16 bytes, got {len(aes_key)}", file=sys.stderr)
        sys.exit(2)

    # Prepare IV and response blob
    iv_req = b64d(args.initial_vector, "initial_vector")
    iv = iv_req[::-1] if args.flip_iv else iv_req
    blob = b64d(args.response_b64, "response_b64")
    if len(blob) < 17:
        print("[!] response too short", file=sys.stderr)
        sys.exit(2)
    ct, tag = blob[:-16], blob[-16:]

    # Decrypt response
    try:
        if USE_VARLEN:
            if AES_varlen is None:
                print("[!] ALLOW_VARLEN_IV=true requires pycryptodome", file=sys.stderr)
                sys.exit(2)
            cipher = AES_varlen.new(aes_key, AES_varlen.MODE_GCM, nonce=iv)
            pt = cipher.decrypt_and_verify(ct, tag)
        else:
            if len(iv) != 12:
                print(f"[!] IV must be 12 bytes in strict mode, got {len(iv)}", file=sys.stderr)
                sys.exit(2)
            pt = AESGCM(aes_key).decrypt(iv, ct + tag, None)
    except Exception as e:
        print(f"[!] AES-GCM decrypt failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        obj = json.loads(pt.decode("utf-8"))
        print("[OK] Decrypted JSON:")
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    except Exception:
        print("[OK] Decrypted bytes:")
        print(pt)

if __name__ == "__main__":
    main()
