import os
import json
import base64
import uuid
from datetime import datetime, timezone

import boto3
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# --- helpers ---

def base64url(raw: bytes) -> str:
    """Base64 URL-safe, no padding (JWK style)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_keypair():
    """
    Generate an Ed25519 keypair and return:
      - public JWK dict (to store in Dynamo / publish in .well-known)
      - private key as base64url string (to show once to the agent owner)
    """
    # private + public Ed25519 keys
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    kid = uuid.uuid4().hex  # key id

    jwk_public = {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": kid,
        "x": base64url(pub_raw),
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

def lambda_handler(event, context):
    """
    Very simple: any POST to this Lambda will create a new agent.

    Later you can:
      - inspect event["requestContext"]["http"]["method"],
      - parse body, etc.
    For now we ignore the body and just create a fresh agent.
    """

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
        "publicKeyJwk": public_jwk,
        # Important: only returned once – agent must store it securely.
        "privateKeyBase64": private_b64,
    }

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            # CORS for your browser UI:
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }
