import json
import os
import logging
import datetime
import decimal
import hmac
import hashlib

import boto3
import stripe

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
            "Access-Control-Allow-Headers": "Content-Type,X-Human-Token,Sec-Client-Class,Signature-Agent,Authorization,Sec-Token",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body, default=decimal_default),
    }


def get_header_map(event):
    headers = event.get("headers") or {}
    return {k.lower(): v for k, v in headers.items()}


def today_iso():
    return datetime.date.today().isoformat()


# ---------- AWS + Stripe clients ----------

dynamodb = boto3.resource("dynamodb")

HAP_STATS_TABLE = os.environ.get("HAP_STATS_TABLE", "hap_stats")
AGENT_WALLETS_TABLE = os.environ.get("AGENT_WALLETS_TABLE", "HAP_AGENT_WALLETS")
PAYMENT_SESSIONS_TABLE = os.environ.get("PAYMENT_SESSIONS_TABLE", "HAP_PAYMENT_SESSIONS")

stats_table = dynamodb.Table(HAP_STATS_TABLE)
wallets_table = dynamodb.Table(AGENT_WALLETS_TABLE)
sessions_table = dynamodb.Table(PAYMENT_SESSIONS_TABLE)

AGENT_SHARED_SECRET = os.environ.get("AGENT_SHARED_SECRET", "")

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
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

def build_canonical_string(event, sig_agent: str) -> str:
    ctx = event.get("requestContext") or {}
    http = ctx.get("http") or {}
    method = (http.get("method") or "GET").upper()
    raw_path = event.get("rawPath") or ctx.get("path") or "/"
    raw_qs = event.get("rawQueryString") or ""
    return "\n".join([method, raw_path, raw_qs, sig_agent or ""])


def verify_agent_request(event):
    headers = get_header_map(event)
    client_class = headers.get("sec-client-class", "").lower()
    sig_agent = headers.get("signature-agent")

    if client_class != "agent":
        return False, None, build_response(
            401,
            {
                "status": "unauthorized",
                "kind": "agent",
                "message": "Missing or invalid Sec-Client-Class: agent.",
            },
        )

    auth = headers.get("authorization", "")
    prefix = "hap-sig "
    if not auth.lower().startswith(prefix):
        return False, None, build_response(
            401,
            {
                "status": "unauthorized",
                "kind": "agent",
                "message": "Missing HAP-Sig Authorization header.",
            },
        )

    if not AGENT_SHARED_SECRET:
        log("agent_auth_misconfig", reason="AGENT_SHARED_SECRET env not set")
        return False, None, build_response(
            500,
            {
                "status": "error",
                "kind": "agent",
                "message": "Server misconfigured for agent auth.",
            },
        )

    provided_sig = auth[len(prefix):]
    canonical = build_canonical_string(event, sig_agent or "")
    expected_sig = hmac.new(
        AGENT_SHARED_SECRET.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    log(
        "agent_auth_attempt",
        sig_agent=sig_agent,
        canonical=canonical,
    )

    if not hmac.compare_digest(provided_sig, expected_sig):
        increment_stat("unknown")
        return False, None, build_response(
            401,
            {
                "status": "unauthorized",
                "kind": "agent",
                "message": "HAP-Sig signature invalid for this agent request.",
            },
        )

    agent_id = sig_agent or "unknown-agent"
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


# ---------- Handlers ----------

def handle_stats_summary(event):
    """
    GET /api/stats/summary

    Returns overall totals + per-day breakdown.

    Example shape:
    {
      "status": "ok",
      "total_days": 2,
      "counts": {
        "human": 2,
        "agent": 4,
        "unknown": 1
      },
      "days": [
        {
          "day": "2025-11-28",
          "counts": { "human": 1, "agent": 3, "unknown": 1 }
        },
        {
          "day": "2025-11-29",
          "counts": { "human": 1, "agent": 1, "unknown": 0 }
        }
      ]
    }
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
    from_airport = qs.get("from")
    to_airport = qs.get("to")
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
            # No credits – return 402 with checkout URL
            session_id, checkout_url = create_checkout_session(agent_id)
            increment_stat("agent")  # still counts as agent traffic
            return build_response(
                402,
                {
                    "status": "payment_required",
                    "kind": "agent",
                    "message": "Agent has no credits; complete payment to continue.",
                    "checkoutUrl": checkout_url,
                    "checkoutSessionId": session_id,
                    "creditsPerPurchase": DEFAULT_AGENT_TOPUP_CREDITS,
                },
            )

        # Deduct one credit and return flights
        remaining = change_wallet_credits(agent_id, -1)
        increment_stat("agent")

        body = {
            "kind": "agent",
            "auth": "HAP-Sig (demo HMAC)",
            "signatureAgent": agent_id,
            "creditsRemaining": remaining,
            "from": from_airport,
            "to": to_airport,
            "date": date,
            "results": fake_flight_results(from_airport, to_airport, date),
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
            "results": fake_flight_results(from_airport, to_airport, date),
        }
        return build_response(200, body)

    # Unknown / bot lane
    increment_stat("unknown")
    body = {
        "status": "forbidden",
        "kind": "unknown",
        "message": "Request is neither a validated human (no X-Human-Token / Sec-Token) nor a declared agent (no Signature-Agent / Sec-Client-Class).",
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
