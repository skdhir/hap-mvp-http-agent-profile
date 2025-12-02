import os
import json
import base64
import uuid
from datetime import datetime, timezone
import time
import hmac
import hashlib

import boto3
from ecdsa import SigningKey, NIST256p

# --- helpers ---

# --- helpers ---
def base64url(raw: bytes) -> str:
    """Base64 URL-safe, no padding (JWK style)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Base64 URL-safe decode with padding fix."""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def verify_token(token: str):
    """
    Verify HMAC-signed token issued by your auth service.

    token = base64(payload_json) + "." + base64(sig)
    where sig = HMAC-SHA256(HAP_AUTH_SECRET, payload_json)
    """
    if not HAP_AUTH_SECRET or not token:
        return None

    try:
        data_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        return None

    try:
        data = b64url_decode(data_b64)
        sig = b64url_decode(sig_b64)
    except Exception:
        return None

    expected_sig = hmac.new(
        HAP_AUTH_SECRET.encode("utf-8"), data, hashlib.sha256
    ).digest()

    if not hmac.compare_digest(sig, expected_sig):
        return None

    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception:
        return None

    # Optional: expiry check (expects "exp" in seconds)
    exp = payload.get("exp")
    if exp and time.time() > float(exp):
        return None

    return payload

def generate_keypair():
    """
    Generate an ECDSA P-256 keypair and return:
      - public JWK dict (to store in Dynamo / publish in .well-known)
      - private key as base64url string (to show once to the agent owner)
      - keyId (kid)
    """
    # Generate private + public ECDSA key (P-256)
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.get_verifying_key()

    # Private key bytes (32 bytes)
    priv_raw = sk.to_string()

    # Public key bytes: 64 bytes = X(32) || Y(32)
    pub_raw = vk.to_string()
    x_bytes = pub_raw[:32]
    y_bytes = pub_raw[32:]

    kid = uuid.uuid4().hex

    jwk_public = {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",   # ECDSA over P-256 with SHA-256
        "kid": kid,
        "x": base64url(x_bytes),
        "y": base64url(y_bytes),
    }
    private_b64 = base64url(priv_raw)

    return jwk_public, private_b64, kid

def now_iso():
    return datetime.now(timezone.utc).isoformat()
# --- Dynamo setup ---

dynamodb = boto3.resource("dynamodb")
AGENTS_TABLE_NAME = os.environ.get("HAP_AGENTS_TABLE", "HAP_AGENTS")
agents_table = dynamodb.Table(AGENTS_TABLE_NAME)

HAP_AUTH_SECRET = os.environ.get("HAP_AUTH_SECRET", "")

# --- Lambda handler ---
dynamodb = boto3.resource("dynamodb")
AGENTS_TABLE_NAME = os.environ.get("HAP_AGENTS_TABLE", "HAP_AGENTS")
agents_table = dynamodb.Table(AGENTS_TABLE_NAME)

def lambda_handler(event, context):
    # If this is a dedicated 'hap-agents-api' Lambda, you can assume POST.
    # If this is inside hap-travel-api with routing, you might be calling
    # handle_create_agent(...) from your main router instead.
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    if method != "POST":
        return {
            "statusCode": 405,
            "headers": {
                "Allow": "POST",
                "Access-Control-Allow-Origin": "*",
            },
            "body": "Method not allowed",
        }

    # --- authenticate caller (agent developer) ---
    headers = event.get("headers") or {}
    headers_lower = { (k or "").lower(): v for k, v in headers.items() }

    auth = headers_lower.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps({
                "status": "unauthorized",
                "message": "Missing Authorization Bearer token",
            }),
        }

    token = auth.split(" ", 1)[1]
    payload = verify_token(token)
    if not payload:
        return {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps({
                "status": "unauthorized",
                "message": "Invalid or expired token",
            }),
        }

    owner_email = (payload.get("sub") or payload.get("email") or "").strip().lower()
    if not owner_email:
        return {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps({
                "status": "unauthorized",
                "message": "Token missing subject/email",
            }),
        }

    # 1) Generate keypair
    public_jwk, private_b64, kid = generate_keypair()

    # 2) Make an agentId
    agent_id = "agent_" + uuid.uuid4().hex

    # 3) Write to DynamoDB (NO private key stored)
    item = {
        "agentId": agent_id,
        "keyId": kid,
        "publicKeyJwk": public_jwk,
        "class": "agent",
        "status": "active",
        "ownerEmail": owner_email,
        "createdAt": now_iso(),
    }

    agents_table.put_item(Item=item)

    # 4) Return response with public JWK + private key
    body = {
        "agentId": agent_id,
        "keyId": kid,
        "publicKeyJwk": public_jwk,
        # Important: only returned once – agent must store it securely.
        "privateKeyBase64": private_b64,
        "ownerEmail": owner_email,
        "createdAt": item["createdAt"],
    }

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }