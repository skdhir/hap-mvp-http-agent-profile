import uuid
import time
import secrets
import json
import os
import logging
import datetime
import decimal
import hashlib
import base64
import time

import boto3
import stripe
import requests
from ecdsa import VerifyingKey, NIST256p, BadSignatureError

# ---------- Logging setup ----------

logger = logging.getLogger()
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)


def log(event_name: str, **fields):
    """
    Structured logger so CloudWatch lines are easy to search.

    Example line:
    {"component": "hap-travel-api", "event": "agent_request", "route": "/api/flights/search", ...}
    """
    payload = {
        "component": "hap-travel-api",
        "event": event_name,
    }
    payload.update(fields)
    try:
        logger.info(json.dumps(payload, default=str))
    except Exception:
        # Fallback – never let logging raise
        logger.info(f"{event_name}: {fields}")


# ---------- Helpers ----------

def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def load_verifying_key_from_jwk(jwk: dict) -> VerifyingKey:
    """
    Convert a P-256 EC JWK to an ecdsa.VerifyingKey.
    Expects:
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "<b64url>",
        "y": "<b64url>",
        ...
      }
    """
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Unsupported key type for agent public key")

    x_bytes = b64url_decode(jwk["x"])
    y_bytes = b64url_decode(jwk["y"])

    # ecdsa library wants raw uncompressed point: x || y (64 bytes)
    return VerifyingKey.from_string(x_bytes + y_bytes, curve=NIST256p)


def build_signing_string(method: str, path_with_query: str, body_bytes: bytes, timestamp: str) -> str:
    """
    EXACTLY matches what the Colab agent signs:

        <METHOD>\n<PATH_WITH_QUERY>\n<TIMESTAMP>\n<SHA256_HEX(body)>
    """
    body_hash = hashlib.sha256(body_bytes or b"").hexdigest()
    return f"{method.upper()}\n{path_with_query}\n{timestamp}\n{body_hash}"


def decimal_default(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    raise TypeError


def build_response(status_code: int, body: dict):
    """
    Standard API Gateway HTTP API response with CORS for the travel.sanatdhir.com UI.
    """
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "https://travel.sanatdhir.com",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": (
                "Content-Type,"
                "X-Human-Token,"
                "Sec-Client-Class,"
                "Signature-Agent,"
                "Authorization,"
                "Sec-Token,"
                "HAP-Agent-Id,"
                "HAP-Signature,"
                "X-HAP-Timestamp"
            ),
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body, default=decimal_default),
    }


def get_header_map(event):
    headers = event.get("headers") or {}
    return {k.lower(): v for k, v in headers.items()}


def today_iso():
    return datetime.date.today().isoformat()

# ---------- Simple auth helpers (MVP-grade) ----------

def hash_password(password: str) -> str:
    """
    Hash password with PBKDF2-HMAC-SHA256.
    Returns salt:hash in base64url.
    """
    if not password:
        raise ValueError("Password required")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{b64url_encode(salt)}:{b64url_encode(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, hash_b64 = stored.split(":", 1)
        salt = b64url_decode(salt_b64)
        stored_dk = b64url_decode(hash_b64)
    except Exception:
        return False

    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return hmac.compare_digest(stored_dk, dk)


def sign_token(payload: dict) -> str:
    """
    Very simple HMAC-signed token.
    token = base64(payload_json) + "." + base64(sig)
    where sig = HMAC-SHA256(secret, payload_json)
    """
    if not HAP_AUTH_SECRET:
        raise RuntimeError("HAP_AUTH_SECRET not configured")

    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(HAP_AUTH_SECRET.encode("utf-8"), data, hashlib.sha256).digest()
    return f"{b64url_encode(data)}.{b64url_encode(sig)}"


def verify_token(token: str):
    """
    Returns payload dict if valid & not expired, else None.
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

    expected_sig = hmac.new(HAP_AUTH_SECRET.encode("utf-8"), data, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected_sig):
        return None

    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception:
        return None

    exp = payload.get("exp")
    if exp and time.time() > float(exp):
        return None

    return payload


def get_current_user(event):
    """
    Reads Authorization: Bearer <token> from headers
    and returns payload (incl. "sub" email) or None.
    """
    headers = get_header_map(event)
    auth = headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1]
    return verify_token(token)

# ---------- AWS + Stripe clients ----------

dynamodb = boto3.resource("dynamodb")

HAP_STATS_TABLE = os.environ.get("HAP_STATS_TABLE", "hap_stats")
AGENT_WALLETS_TABLE = os.environ.get("AGENT_WALLETS_TABLE", "HAP_AGENT_WALLETS")
PAYMENT_SESSIONS_TABLE = os.environ.get("PAYMENT_SESSIONS_TABLE", "HAP_PAYMENT_SESSIONS")
AGENTS_TABLE_NAME = os.environ.get("HAP_AGENTS_TABLE", "HAP_AGENTS")
USERS_TABLE_NAME = os.environ.get("HAP_USERS_TABLE", "HAP_USERS")  # <--- add this
HAP_AUTH_SECRET = os.environ.get("HAP_AUTH_SECRET", "")

# --- Amadeus flight API config ---
AMADEUS_ENABLED = os.environ.get("AMADEUS_ENABLED", "false").lower() == "true"
AMADEUS_CLIENT_ID = os.environ.get("AMADEUS_CLIENT_ID")
AMADEUS_CLIENT_SECRET = os.environ.get("AMADEUS_CLIENT_SECRET")
AMADEUS_ENV = os.environ.get("AMADEUS_ENV", "test")

# Simple in-memory token cache for this Lambda execution environment
_amadeus_access_token = None
_amadeus_token_expiry = 0.0  # epoch seconds

stats_table = dynamodb.Table(HAP_STATS_TABLE)
wallets_table = dynamodb.Table(AGENT_WALLETS_TABLE)
sessions_table = dynamodb.Table(PAYMENT_SESSIONS_TABLE)
agents_table = dynamodb.Table(AGENTS_TABLE_NAME)
users_table = dynamodb.Table(USERS_TABLE_NAME)  # <--- add this

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
# Default autopay amount if not overridden per agent (in cents)
AUTOPAY_DEFAULT_AMOUNT_CENTS = 100  # $1.00 for DEFAULT_AGENT_TOPUP_CREDITS
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")
STRIPE_SUCCESS_URL = os.environ.get("STRIPE_SUCCESS_URL", "")
STRIPE_CANCEL_URL = os.environ.get("STRIPE_CANCEL_URL", "")

# How many credits one Stripe Checkout gives
DEFAULT_AGENT_TOPUP_CREDITS = 100


# ---------- Stats ----------

def increment_stat(kind: str, delta: int = 1):
    """
    Increment hap_stats[day, kind].count by delta.
    """
    day = today_iso()
    try:
        stats_table.update_item(
            Key={"day": day, "kind": kind},
            UpdateExpression="ADD #count :inc",
            ExpressionAttributeNames={"#count": "count"},
            ExpressionAttributeValues={":inc": decimal.Decimal(delta)},
        )
        log("stat_increment", day=day, kind=kind, delta=delta)
    except Exception as e:
        log("stat_increment_error", day=day, kind=kind, error=str(e))


def load_stats_summary():
    day = today_iso()
    result = {"day": day, "counts": {"human": 0, "agent": 0, "unknown": 0}}
    try:
        for kind in ["human", "agent", "unknown"]:
            resp = stats_table.get_item(Key={"day": day, "kind": kind})
            count = resp.get("Item", {}).get("count", decimal.Decimal(0))
            result["counts"][kind] = int(count)
        return result
    except Exception as e:
        log("stats_summary_error", error=str(e))
        return result


# ---------- Agent wallet helpers ----------

def get_wallet(agent_id: str):
    resp = wallets_table.get_item(Key={"agentId": agent_id})
    return resp.get("Item")


def ensure_wallet(agent_id: str):
    item = get_wallet(agent_id)
    if item:
        return item

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    item = {
        "agentId": agent_id,
        "credits": decimal.Decimal(0),
        "updatedAt": now,
    }
    wallets_table.put_item(Item=item)
    log("wallet_created", agentId=agent_id)
    return item


def change_wallet_credits(agent_id: str, delta: int):
    """
    Atomically add delta to credits (can be negative).
    Returns the new credits count.
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    resp = wallets_table.update_item(
        Key={"agentId": agent_id},
        UpdateExpression="ADD credits :delta SET updatedAt = :now",
        ExpressionAttributeValues={
            ":delta": decimal.Decimal(delta),
            ":now": now,
        },
        ReturnValues="ALL_NEW",
    )
    new_item = resp["Attributes"]
    log("wallet_updated", agentId=agent_id, delta=delta, credits=int(new_item["credits"]))
    return int(new_item["credits"])


# ---------- Agent auth + payments ----------

def verify_agent_signature(event, headers_lower):
    """
    Verify the ECDSA signature from your agent.

    Returns:
      (ok: bool, value: str)
        if ok is True: value = agentId
        if ok is False: value = error message
    """
    agent_id = headers_lower.get("hap-agent-id")
    hap_sig = headers_lower.get("hap-signature")
    ts = headers_lower.get("x-hap-timestamp")

    if not (agent_id and hap_sig and ts):
        return False, "Missing HAP agent signature headers"

    if not hap_sig.startswith("v0:"):
        return False, "Unsupported HAP-Signature version"

    sig_b64 = hap_sig.split(":", 1)[1]
    try:
        sig_bytes = b64url_decode(sig_b64)
    except Exception:
        return False, "Malformed signature encoding"

    # Reconstruct the same path_with_query that Colab signed
    method = event["requestContext"]["http"]["method"]
    raw_path = event.get("rawPath") or event["requestContext"]["http"]["path"]
    raw_query = event.get("rawQueryString") or ""
    if raw_query:
        path_with_query = f"{raw_path}?{raw_query}"
    else:
        path_with_query = raw_path

    body_str = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body_bytes = base64.b64decode(body_str)
    else:
        body_bytes = body_str.encode("utf-8")

    signing_string = build_signing_string(method, path_with_query, body_bytes, ts)

    # Look up the agent's public key in HAP_AGENTS
    resp = agents_table.get_item(Key={"agentId": agent_id})
    item = resp.get("Item")
    if not item:
        return False, "Unknown agentId"

    jwk = item.get("publicKeyJwk")
    if isinstance(jwk, str):
        jwk = json.loads(jwk)

    try:
        vk = load_verifying_key_from_jwk(jwk)
        vk.verify(sig_bytes, signing_string.encode("utf-8"))
    except BadSignatureError:
        return False, "Invalid agent signature"
    except Exception as e:
        return False, f"Error verifying signature: {str(e)}"

    return True, agent_id


def verify_agent_request(event):
    """
    Verify that this is a properly signed agent request using ECDSA.

    Returns:
      (verified: bool, agent_id: str | None, error_response: dict | None)
    """
    headers = get_header_map(event)
    client_class = headers.get("sec-client-class", "").lower()

    # 1) Must clearly declare itself as an agent
    if client_class != "agent":
        return False, None, build_response(
            401,
            {
                "status": "unauthorized",
                "kind": "agent",
                "message": "Missing or invalid Sec-Client-Class: agent.",
            },
        )

    # 2) Verify the ECDSA signature using headers + event
    headers_lower = headers  # already lower‑cased by get_header_map
    ok, result = verify_agent_signature(event, headers_lower)

    if not ok:
        # result is an error message string like "Unknown agentId" or "Invalid agent signature"
        return False, None, build_response(
            401,
            {
                "status": "unauthorized",
                "kind": "agent",
                "message": result,
            },
        )

    # 3) Success – result is the verified agentId
    agent_id = result
    return True, agent_id, None


def create_checkout_session(agent_id: str, credits: int = DEFAULT_AGENT_TOPUP_CREDITS):
    """
    Create a Stripe Checkout Session to top up the agent wallet.
    """
    if not stripe.api_key or not STRIPE_PRICE_ID:
        log(
            "stripe_misconfig",
            has_api_key=bool(stripe.api_key),
            price_id=STRIPE_PRICE_ID,
        )
        return None, None

    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[
            {
                "price": STRIPE_PRICE_ID,
                "quantity": 1,
            }
        ],
        success_url=STRIPE_SUCCESS_URL,
        cancel_url=STRIPE_CANCEL_URL,
        metadata={
            "agent_id": agent_id,
            "credits": str(credits),
        },
    )

    # Record in HAP_PAYMENT_SESSIONS as pending
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        sessions_table.put_item(
            Item={
                "sessionId": session.id,
                "agentId": agent_id,
                "createdAt": now,
                "creditsPurchased": decimal.Decimal(credits),
                "status": "pending",
                "mode": "manual",
            }
        )
        log(
            "payment_session_created",
            sessionId=session.id,
            agentId=agent_id,
            credits=credits,
        )
    except Exception as e:
        log("payment_session_put_error", sessionId=session.id, error=str(e))

    return session.id, session.url

def maybe_autopay_topup(agent_id: str, current_credits: int):
    """
    Try to automatically top up this agent's wallet if autopay is enabled.

    Returns:
      (topped_up: bool, new_credits: int, error: str | None)
    """
    # 1) Look up agent config (autopay flags, Stripe IDs, etc.)
    try:
        resp = agents_table.get_item(Key={"agentId": agent_id})
        agent = resp.get("Item")
    except Exception as e:
        log("autopay_agent_lookup_error", agentId=agent_id, error=str(e))
        return False, current_credits, "agent_lookup_failed"

    if not agent:
        log("autopay_disabled_no_agent", agentId=agent_id)
        return False, current_credits, "no_agent_record"

    # 2) Is autopay enabled?
    enabled = agent.get("autopayEnabled")
    if isinstance(enabled, str):
        enabled = enabled.lower() in ("1", "true", "yes", "y")
    if not enabled:
        return False, current_credits, "autopay_not_enabled"

    customer_id = agent.get("stripeCustomerId")
    if not customer_id:
        log("autopay_missing_stripe_customer", agentId=agent_id)
        return False, current_credits, "missing_stripe_customer"

    topup_credits = int(agent.get("autopayTopupCredits", DEFAULT_AGENT_TOPUP_CREDITS))
    amount_cents = int(agent.get("autopayAmountCents", AUTOPAY_DEFAULT_AMOUNT_CENTS))
    currency = agent.get("autopayCurrency", "usd")

    # 3) Figure out WHICH payment method to use
    payment_method_id = agent.get("autopayPaymentMethodId")  # optional field in HAP_AGENTS

    # 3a) If not set explicitly, try the customer's default payment method
    if not payment_method_id:
        try:
            customer = stripe.Customer.retrieve(
                customer_id,
                expand=["invoice_settings.default_payment_method"],
            )
            default_pm = customer.get("invoice_settings", {}).get("default_payment_method")
            if isinstance(default_pm, dict):
                payment_method_id = default_pm.get("id")
            elif isinstance(default_pm, str):
                payment_method_id = default_pm
        except Exception as e:
            log(
                "autopay_customer_retrieve_error",
                agentId=agent_id,
                customerId=customer_id,
                error=str(e),
            )

    # 3b) If still nothing, fall back to "first attached card PaymentMethod"
    if not payment_method_id:
        try:
            pms = stripe.PaymentMethod.list(
                customer=customer_id,
                type="card",
                limit=1,
            )
            if pms.data:
                payment_method_id = pms.data[0].id
        except Exception as e:
            log(
                "autopay_paymentmethod_list_error",
                agentId=agent_id,
                customerId=customer_id,
                error=str(e),
            )

    if not payment_method_id:
        # At this point we truly can't figure out what to charge
        log(
            "autopay_missing_payment_method",
            agentId=agent_id,
            customerId=customer_id,
        )
        return False, current_credits, "missing_payment_method"

    # 4) Create a PaymentIntent using that specific PaymentMethod, off-session
    try:
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            metadata={
                "agent_id": agent_id,
                "autopay": "true",
                "credits": str(topup_credits),
            },
        )
    except stripe.error.CardError as e:
        # This can happen if the bank demands extra auth (3DS etc.)
        log(
            "autopay_card_error",
            agentId=agent_id,
            customerId=customer_id,
            code=getattr(e, "code", None),
            message=str(e),
        )
        return False, current_credits, f"card_error_{getattr(e, 'code', 'unknown')}"
    except Exception as e:
        log("autopay_paymentintent_error", agentId=agent_id, error=str(e))
        return False, current_credits, "stripe_error"

    if intent.status != "succeeded":
        # Could be requires_action, requires_payment_method, etc.
        log(
            "autopay_payment_not_succeeded",
            agentId=agent_id,
            status=intent.status,
            intentId=intent.id,
        )
        return False, current_credits, f"payment_status_{intent.status}"

    # 5) Payment succeeded – actually top up the wallet
    new_credits = change_wallet_credits(agent_id, topup_credits)
    log(
        "autopay_wallet_topped_up",
        agentId=agent_id,
        added=topup_credits,
        credits=new_credits,
        paymentIntentId=intent.id,
    )

    # Optional but nice: record in HAP_PAYMENT_SESSIONS so dashboard can show autopay events
    try:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sessions_table.put_item(
            Item={
                "sessionId": intent.id,
                "agentId": agent_id,
                "createdAt": now,
                "paidAt": now,
                "creditsPurchased": decimal.Decimal(topup_credits),
                "status": "succeeded",
                "mode": "auto",
            }
        )
        log(
            "autopay_session_recorded",
            agentId=agent_id,
            sessionId=intent.id,
        )
    except Exception as e:
        log(
            "autopay_session_put_error",
            agentId=agent_id,
            sessionId=intent.id,
            error=str(e),
        )

    return True, new_credits, None

# ---------- Handlers ----------

def handle_auth_signup(event):
    """
    POST /api/auth/signup
    Body: { "email": "...", "password": "..." }
    """
    try:
        body_raw = event.get("body") or ""
        if event.get("isBase64Encoded"):
            body_raw = base64.b64decode(body_raw).decode("utf-8")
        data = json.loads(body_raw) if body_raw else {}
    except Exception:
        return build_response(400, {"status": "bad_request", "message": "Invalid JSON body"})

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or "@" not in email:
        return build_response(400, {"status": "bad_request", "message": "Valid email required"})
    if not password or len(password) < 8:
        return build_response(400, {"status": "bad_request", "message": "Password must be at least 8 characters"})

    # Check if user exists
    try:
        resp = users_table.get_item(Key={"email": email})
        if "Item" in resp:
            return build_response(409, {"status": "conflict", "message": "User already exists"})
    except Exception as e:
        log("auth_signup_get_error", error=str(e))
        return build_response(500, {"status": "error", "message": "Internal error"})

    try:
        pw_hash = hash_password(password)
    except Exception as e:
        log("auth_signup_hash_error", error=str(e))
        return build_response(500, {"status": "error", "message": "Internal error"})

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    item = {
        "email": email,
        "passwordHash": pw_hash,
        "createdAt": now,
    }

    try:
        users_table.put_item(Item=item)
        log("auth_user_created", email=email)
    except Exception as e:
        log("auth_signup_put_error", error=str(e))
        return build_response(500, {"status": "error", "message": "Internal error"})

    # Issue token immediately
    payload = {
        "sub": email,
        "email": email,
        "iat": int(time.time()),
        "exp": int(time.time()) + 7 * 24 * 3600,  # 7 days
    }
    token = sign_token(payload)

    return build_response(
        200,
        {
            "status": "ok",
            "user": {"email": email},
            "token": token,
        },
    )

def handle_auth_login(event):
    """
    POST /api/auth/login
    Body: { "email": "...", "password": "..." }
    """
    try:
        body_raw = event.get("body") or ""
        if event.get("isBase64Encoded"):
            body_raw = base64.b64decode(body_raw).decode("utf-8")
        data = json.loads(body_raw) if body_raw else {}
    except Exception:
        return build_response(400, {"status": "bad_request", "message": "Invalid JSON body"})

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return build_response(400, {"status": "bad_request", "message": "Email and password required"})

    try:
        resp = users_table.get_item(Key={"email": email})
        item = resp.get("Item")
    except Exception as e:
        log("auth_login_get_error", error=str(e))
        return build_response(500, {"status": "error", "message": "Internal error"})

    if not item:
        return build_response(401, {"status": "unauthorized", "message": "Invalid credentials"})

    pw_hash = item.get("passwordHash")
    if not verify_password(password, pw_hash or ""):
        return build_response(401, {"status": "unauthorized", "message": "Invalid credentials"})

    payload = {
        "sub": email,
        "email": email,
        "iat": int(time.time()),
        "exp": int(time.time()) + 7 * 24 * 3600,
    }
    token = sign_token(payload)

    return build_response(
        200,
        {
            "status": "ok",
            "user": {"email": email},
            "token": token,
        },
    )

def handle_stats_summary(event):
    """
    GET /api/stats/summary

    Returns overall totals + per-day breakdown.
    """
    per_day = {}  # { "YYYY-MM-DD": {"human": 0, "agent": 0, "unknown": 0}, ... }

    try:
        # Scan entire table (fine at current scale).
        resp = stats_table.scan()
        items = resp.get("Items", [])

        for item in items:
            day = item.get("day")
            kind = item.get("kind")
            if not day or not kind:
                continue

            if day not in per_day:
                per_day[day] = {"human": 0, "agent": 0, "unknown": 0}

            if kind in per_day[day]:
                try:
                    per_day[day][kind] = int(item.get("count", 0))
                except Exception:
                    # if bad/missing count, leave as 0
                    pass

    except Exception as e:
        print(f"handle_stats_summary error while scanning table: {e}")
        return build_response(
            500,
            {
                "status": "error",
                "message": str(e),
                "total_days": 0,
                "counts": {"human": 0, "agent": 0, "unknown": 0},
                "days": [],
            },
        )

    if not per_day:
        # No stats at all yet
        return build_response(
            200,
            {
                "status": "ok",
                "total_days": 0,
                "counts": {"human": 0, "agent": 0, "unknown": 0},
                "days": [],
            },
        )

    # Build the per-day list sorted by day
    days_list = [
        {"day": day, "counts": per_day[day]}
        for day in sorted(per_day.keys())
    ]

    # Compute totals across all days
    totals = {"human": 0, "agent": 0, "unknown": 0}
    for day_counts in per_day.values():
        for kind in totals.keys():
            totals[kind] += int(day_counts.get(kind, 0))

    body = {
        "status": "ok",
        "total_days": len(per_day),
        "counts": totals,
        "days": days_list,
    }
    return build_response(200, body)


def handle_billing_agents(event):
    """
    Simple billing/agent snapshot used by dashboard.
    """
    # Load wallets
    wallets = []
    try:
        resp = wallets_table.scan()
        for item in resp.get("Items", []):
            wallets.append(
                {
                    "agentId": item.get("agentId"),
                    "credits": int(item.get("credits", 0)),
                    "updatedAt": item.get("updatedAt"),
                }
            )
    except Exception as e:
        log("billing_wallets_scan_error", error=str(e))

    # Load payment sessions summary
    sessions_summary = {
        "total": 0,
        "byStatus": {},
    }
    try:
        resp = sessions_table.scan()
        items = resp.get("Items", [])
        sessions_summary["total"] = len(items)
        counts = {}
        for it in items:
            status = it.get("status", "unknown")
            counts[status] = counts.get(status, 0) + 1
        sessions_summary["byStatus"] = counts
    except Exception as e:
        log("billing_sessions_scan_error", error=str(e))

    body = {
        "status": "ok",
        "wallets": wallets,
        "paymentSessions": sessions_summary,
    }
    return build_response(200, body)

# ---------- Amadeus helpers ----------

def amadeus_base_url() -> str:
    """
    Use the test or production base URL depending on AMADEUS_ENV.
    """
    if AMADEUS_ENV == "production":
        return "https://api.amadeus.com"
    return "https://test.api.amadeus.com"


def get_amadeus_access_token() -> Optional[str]:
    """
    Get (and cache) an OAuth2 access token for Amadeus.
    Returns None if credentials are missing or the call fails.
    """
    global _amadeus_access_token, _amadeus_token_expiry

    if not (AMADEUS_ENABLED and AMADEUS_CLIENT_ID and AMADEUS_CLIENT_SECRET):
        enabled=AMADEUS_ENABLED,
        has_id=bool(AMADEUS_CLIENT_ID),
        has_secret=bool(AMADEUS_CLIENT_SECRET),
        log("amadeus_disabled", reason=f"missing_credentials, enabled/has_id/has_secret= {enabled}/{has_id}/{has_secret}")
        return None

    now = time.time()
    # Reuse token if it exists and is not about to expire
    if _amadeus_access_token and now < _amadeus_token_expiry - 30:
        return _amadeus_access_token

    token_url = amadeus_base_url() + "/v1/security/oauth2/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": AMADEUS_CLIENT_ID,
        "client_secret": AMADEUS_CLIENT_SECRET,
    }

    try:
        resp = requests.post(
            token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5,
        )
    except Exception as e:
        log("amadeus_token_http_error", error=str(e))
        return None

    if resp.status_code != 200:
        log("amadeus_token_bad_status", status=resp.status_code, body=resp.text[:300])
        return None

    try:
        payload = resp.json()
    except Exception as e:
        log("amadeus_token_json_error", error=str(e), body=resp.text[:200])
        return None

    token = payload.get("access_token")
    expires_in = int(payload.get("expires_in", 1800))
    if not token:
        log("amadeus_token_missing", payload=payload)
        return None

    _amadeus_access_token = token
    _amadeus_token_expiry = now + expires_in
    log("amadeus_token_ok", expires_in=expires_in)
    return token


def amadeus_search_flights(from_airport: str, to_airport: str, date: str):
    """
    Call Amadeus Flight Offers Search (simple GET flavor) and return
    a list of simplified flight dicts.
    Falls back to [] or fake flights if anything goes wrong.
    """
    token = get_amadeus_access_token()
    if not token:
        # If we can't get a token, just signal "no real data"
        return None

    url = amadeus_base_url() + "/v2/shopping/flight-offers"
    params = {
        "originLocationCode": from_airport,
        "destinationLocationCode": to_airport,
        "departureDate": date,
        "adults": "1",
        "max": "5",
    }

    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=8,
        )
    except Exception as e:
        log("amadeus_search_http_error", error=str(e))
        return None

    if resp.status_code != 200:
        log(
            "amadeus_search_bad_status",
            status=resp.status_code,
            body=resp.text[:300],
        )
        return None

    try:
        payload = resp.json()
    except Exception as e:
        log("amadeus_search_json_error", error=str(e), body=resp.text[:200])
        return None

    offers = payload.get("data", [])
    if not offers:
        log("amadeus_search_empty", from_airport=from_airport, to_airport=to_airport, date=date)
        return []

    results = []

    for offer in offers[:5]:
        itineraries = offer.get("itineraries") or []
        if not itineraries:
            continue
        itinerary = itineraries[0]
        segments = itinerary.get("segments") or []
        if not segments:
            continue

        first_seg = segments[0]
        last_seg = segments[-1]

        dep = first_seg.get("departure", {}) or {}
        arr = last_seg.get("arrival", {}) or {}

        carrier = first_seg.get("carrierCode")
        number = first_seg.get("number")
        price_info = offer.get("price") or {}
        currency = price_info.get("currency", "USD")
        total = price_info.get("total")

        def split_dt(dt: Optional[str]):
            if not dt or "T" not in dt:
                return None, None
            d, t = dt.split("T", 1)
            return d, t[:5]

        dep_date, dep_time = split_dt(dep.get("at"))
        arr_date, arr_time = split_dt(arr.get("at"))

        results.append(
            {
                "flightNumber": f"{carrier}{number}" if carrier and number else number or "",
                "airline": carrier,
                "from": dep.get("iataCode") or from_airport,
                "to": arr.get("iataCode") or to_airport,
                "date": dep_date or date,
                "departureTime": dep_time,
                "arrivalTime": arr_time,
                "priceCurrency": currency,
                "priceTotal": float(total) if total is not None else None,
            }
        )

    return results


def get_flight_results(from_airport: str, to_airport: str, date: str):
    """
    Main hook used by the handler:
    - Try Amadeus first (if configured)
    - Fallback to fake flights if Amadeus is disabled or fails
    """
    real = amadeus_search_flights(from_airport, to_airport, date)
    if real is None:
        # e.g. credentials missing or token/search error
        return fake_flight_results(from_airport, to_airport, date)
    return real


def fake_flight_results(from_airport: str, to_airport: str, date: str):
    return [
        {
            "flightNumber": "HAP101",
            "airline": "HAP Airways",
            "from": from_airport,
            "to": to_airport,
            "date": date,
            "departureTime": "08:00",
            "arrivalTime": "16:00",
            "priceUsd": 320,
        },
        {
            "flightNumber": "HAP202",
            "airline": "Agentic Air",
            "from": from_airport,
            "to": to_airport,
            "date": date,
            "departureTime": "13:00",
            "arrivalTime": "21:00",
            "priceUsd": 290,
        },
    ]


def handle_flights_search(event):
    headers = get_header_map(event)
    qs = event.get("queryStringParameters") or {}

    # Support both old ("from"/"to") and new ("origin"/"destination") query names
    from_airport = qs.get("from") or qs.get("origin")
    to_airport = qs.get("to") or qs.get("destination")
    date = qs.get("date")

    log(
        "flights_request",
        from_airport=from_airport,
        to_airport=to_airport,
        date=date,
        headers=headers,
    )

    # Agent lane
    if headers.get("sec-client-class", "").lower() == "agent" or "signature-agent" in headers:
        verified, agent_id, error_resp = verify_agent_request(event)
        if not verified:
            return error_resp

        # Ensure wallet + check credits
        wallet = ensure_wallet(agent_id)
        current_credits = int(wallet.get("credits", 0))

        if current_credits <= 0:
            # Try autopay first, if enabled for this agent
            topped_up, current_credits, autopay_error = maybe_autopay_topup(agent_id, current_credits)

            if not topped_up and current_credits <= 0:
                # Still no credits – fall back to manual 402 + Checkout
                session_id, checkout_url = create_checkout_session(agent_id)
                increment_stat("agent")  # still counts as agent traffic

                body = {
                    "status": "payment_required",
                    "kind": "agent",
                    "message": "Agent has no credits; complete payment to continue.",
                    "checkoutUrl": checkout_url,
                    "checkoutSessionId": session_id,
                    "creditsPerPurchase": DEFAULT_AGENT_TOPUP_CREDITS,
                }
                if autopay_error:
                    body["autopayError"] = autopay_error

                return build_response(402, body)

        # At this point, we have > 0 credits (either existing or after autopay).
        remaining = change_wallet_credits(agent_id, -1)
        increment_stat("agent")

        body = {
            "kind": "agent",
            "auth": "HAP ECDSA (v0)",
            "signatureAgent": agent_id,
            "creditsRemaining": remaining,
            "from": from_airport,
            "to": to_airport,
            "date": date,
            "results": get_flight_results(from_airport, to_airport, date),
        }
        return build_response(200, body)

    # Human lane (simulated Private Access Token / human token)
    human_token = headers.get("x-human-token") or headers.get("sec-token")
    if human_token:
        increment_stat("human")
        body = {
            "kind": "human",
            "auth": "X-Human-Token (simulated PAT)",
            "from": from_airport,
            "to": to_airport,
            "date": date,
            "results": get_flight_results(from_airport, to_airport, date),
        }
        return build_response(200, body)

    # Unknown / bot lane
    increment_stat("unknown")
    body = {
        "status": "forbidden",
        "kind": "unknown",
        "message": (
            "Request is neither a validated human (no X-Human-Token / Sec-Token) "
            "nor a declared agent (no Signature-Agent / Sec-Client-Class)."
        ),
        "hint": "Human browsers should send a human token; agents should sign requests.",
    }
    return build_response(403, body)

# ---------- Lambda entrypoint ----------

def lambda_handler(event, context):
    """
    Single entry point for all routes:
    - GET /api/flights/search
    - GET /api/stats/summary
    - GET /api/billing/agents
    """
    route_key = (event.get("requestContext") or {}).get("routeKey")
    raw_path = event.get("rawPath") or "/"
    http = (event.get("requestContext") or {}).get("http") or {}
    method = http.get("method", "GET")

    log(
        "request_received",
        routeKey=route_key,
        rawPath=raw_path,
        method=method,
        requestId=getattr(context, "aws_request_id", None),
    )

    try:
        if raw_path == "/api/flights/search" and method == "GET":
            return handle_flights_search(event)
        if raw_path == "/api/stats/summary" and method == "GET":
            return handle_stats_summary(event)
        if raw_path == "/api/billing/agents" and method == "GET":
            return handle_billing_agents(event)
        if raw_path == "/api/auth/signup" and method == "POST":
            return handle_auth_signup(event)
        if raw_path == "/api/auth/login" and method == "POST":
            return handle_auth_login(event)

        # default 404
        return build_response(
            404,
            {"message": f"No route for {method} {raw_path}"},
        )
    except Exception as e:
        # Catch-all so we never return a Lambda error without logs
        log(
            "unhandled_exception",
            error=str(e),
        )
        return build_response(500, {"message": "Internal Server Error"})
