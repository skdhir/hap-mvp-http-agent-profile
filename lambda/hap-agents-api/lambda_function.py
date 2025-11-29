import os
import json
import base64
import uuid
from datetime import datetime, timezone

import boto3
from ecdsa import SigningKey, NIST256p

# --- helpers ---
def base64url(raw: bytes) -> str:
    """Base64 URL-safe, no padding (JWK style)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


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
            "headers": {"Allow": "POST"},
            "body": "Method not allowed",
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