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

# ---------- Base64 helpers ----------

def base64url(raw: bytes) -> str:
    """Base64 URL-safe, no padding (JWK style, used for JWK fields)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Base64 URL-safe decode with automatic padding."""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


# ---------- Keypair generation ----------

def generate_keypair():
    """
    Generate an ECDSA P-256 keypair and return:
      - public JWK dict (to store in Dynamo / publish in .well-known)
      - private key as base64url string (to show once to the agent owner)
      - keyId (kid)
    """
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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- Dynamo + Auth ----------

dynamodb = boto3.resource("dynamodb")
AGENTS_TABLE_NAME = os.environ.get("HAP_AGENTS_TABLE", "HAP_AGENTS")
agents_table = dynamodb.Table(AGENTS_TABLE_NAME)

# MUST match HAP_AUTH_SECRET used in hap-travel-api
HAP_AUTH_SECRET = os.environ.get("HAP_AUTH_SECRET", "")


def verify_token(token: str):
    """
    Verify HMAC-signed token from hap-travel-api.

    Token format (as issued in hap-travel-api's sign_token):
      token = base64url(payload_json) + "." + base64url(HMAC_SHA256(secret, payload_json))

    payload_json looks like:
      { "sub": "user_xxx", "email": "dev@example.com", "iat": ..., "exp": ... }
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
        HAP_AUTH_SECRET.encode("utf-8"),
        data,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(expected_sig, sig):
        return None

    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception:
        return None

    # Optional expiry check
    exp = payload.get("exp")
    if exp is not None:
        try:
            if time.time() > float(exp):
                return None
        except Exception:
            return None

    return payload


# ---------- Lambda handler ----------

def lambda_handler(event, context):
    """
    POST /api/agents

    Requires:
      Authorization: Bearer <token-from-/api/auth/login>

    Creates:
      - new agentId
      - new P-256 keypair
      - row in HAP_AGENTS with:
          - agentId
          - ownerUserId
          - ownerEmail
          - keyId
          - publicKeyJwk
          - class = "agent"
          - status = "active"
          - createdAt
    """
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

    # --- Authenticate caller (agent developer) ---
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    auth = auth.strip()

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

    token = auth.split(" ", 1)[1].strip()
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

    # NOTE: here we *separate* userId and email
    owner_user_id = (payload.get("sub") or "").strip()
    owner_email = (payload.get("email") or "").strip().lower()

    if not owner_user_id or not owner_email:
        return {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps({
                "status": "unauthorized",
                "message": "Token missing sub/email",
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
        "ownerUserId": owner_user_id,
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
        "ownerUserId": owner_user_id,
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
