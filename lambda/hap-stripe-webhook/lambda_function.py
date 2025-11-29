import os
import json
import base64
from datetime import datetime
from decimal import Decimal

import boto3
import stripe

# Stripe config
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]

# DynamoDB config
dynamodb = boto3.resource("dynamodb")
wallets_table = dynamodb.Table(os.environ["AGENT_WALLETS_TABLE"])
sessions_table = dynamodb.Table(os.environ["PAYMENT_SESSIONS_TABLE"])


def lambda_handler(event, context):
    # 1) Get the raw body that Stripe sent
    payload = event.get("body", "")
    if event.get("isBase64Encoded"):
        payload = base64.b64decode(payload)

    # Stripe sends the signature in this header
    sig_header = (event.get("headers") or {}).get("stripe-signature", "")

    # 2) Verify the webhook signature
    try:
        stripe_event = stripe.Webhook.construct_event(
            payload, sig_header, WEBHOOK_SECRET
        )
    except ValueError:
        # Invalid payload
        print("Invalid payload")
        return {"statusCode": 400, "body": "Invalid payload"}
    except stripe.error.SignatureVerificationError:
        print("Invalid signature")
        return {"statusCode": 400, "body": "Invalid signature"}

    print("Stripe event type:", stripe_event["type"])

    # 3) Handle checkout.session.completed
    if stripe_event["type"] == "checkout.session.completed":
        session = stripe_event["data"]["object"]
        session_id = session["id"]

        # These should match what you set when creating the checkout session
        metadata = session.get("metadata") or {}
        agent_id = metadata.get("agent_id") or "unknown-agent"
        credits_str = metadata.get("credits") or "100"

        try:
            credits = int(credits_str)
        except ValueError:
            credits = 100

        now_iso = datetime.utcnow().isoformat() + "Z"

        # 3a) Mark payment session as paid
        try:
            sessions_table.update_item(
                Key={"sessionId": session_id},
                UpdateExpression="SET #s = :paid, paidAt = :t",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":paid": "paid",
                    ":t": now_iso,
                },
            )
            print(f"Marked session {session_id} as paid")
        except Exception as e:
            print("Error updating sessions table:", repr(e))

        # 3b) Add credits to agent wallet
        try:
            wallets_table.update_item(
                Key={"agentId": agent_id},
                UpdateExpression="ADD credits :c SET updatedAt = :t",
                ExpressionAttributeValues={
                    ":c": Decimal(credits),
                    ":t": now_iso,
                },
            )
            print(f"Added {credits} credits to wallet for {agent_id}")
        except Exception as e:
            print("Error updating wallet:", repr(e))

    # 4) Always return 200 to Stripe
    return {
        "statusCode": 200,
        "body": json.dumps({"received": True}),
    }
