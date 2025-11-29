# HAP Travel – HTTP Agent Profile MVP: AWS Setup Guide

This document describes how to recreate the **HAP Travel – Human vs Agent Traffic** MVP on AWS.

It assumes:

- You have an AWS account.
- You control a domain in **Route 53** (e.g. `sanatdhir.com`).
- You are comfortable with the AWS Console and basic CLI commands.

---

## 1. High‑level architecture

We deploy three main surfaces:

- **Human UI** – `https://travel.<your-domain>`  
  Static frontend (search page + dashboard) hosted in **S3** behind **CloudFront**.

- **HAP gateway API** – `https://api.<your-domain>`  
  HTTP API in **API Gateway** backed by a **Lambda** (`hap-travel-api`).

- **Agent metadata** – `https://agent.<your-domain>`  
  Static S3 site serving `.well-known/http-message-signatures/keys.json` behind CloudFront.

We also use:

- **DynamoDB** for stats, wallets, and payments.
- **Stripe** for test payments (1$ → 100 agent credits).
- A **Google Colab agent client** that calls the API with HAP signatures.

---

## 2. Prerequisites

### 2.1 Tools

On your local machine:

- Git
- Python 3 + pip
- AWS CLI v2
- (optional) Node.js if you later add build tooling for the UI

Configure AWS CLI:

```bash
aws configure
# Region: us-east-1
# Output: json
```

Use an IAM user or SSO profile; **never** commit keys to Git.

### 2.2 Domain in Route 53

You should already have:

- A **Route 53 hosted zone** for `your-domain.com`.
- The domain registered or nameservers pointing to Route 53.

We will use three subdomains:

- `travel.your-domain.com` – human UI.
- `api.your-domain.com` – API Gateway custom domain.
- `agent.your-domain.com` – agent metadata + keys.json.

---

## 3. TLS certificates (ACM)

### 3.1 Create a wildcard certificate (for CloudFront)

1. Go to **ACM (Certificate Manager)** in region **us-east-1**.
2. Click **Request a certificate** → **Request a public certificate**.
3. Add these domain names:
   - `your-domain.com`
   - `*.your-domain.com`
4. Choose **DNS validation**.
5. ACM will create CNAME records in Route 53; click **Create records in Route 53**.
6. Wait until the certificate status is **Issued**.

This single certificate will be used by:

- CloudFront distributions (`travel` & `agent`).
- API Gateway custom domain (if also in us-east-1).

Note: For API Gateway (HTTP API), you can also create a separate ACM cert if you prefer, but the wildcard is often enough.

---

## 4. Static sites: S3 + CloudFront

### 4.1 S3 bucket for human UI

1. Go to **S3** → **Create bucket**.
2. Name: `travel.your-domain.com`.
3. Region: `us-east-1`.
4. Uncheck “Block all public access” **only if** you later restrict access to CloudFront; a secure setup is:
   - Keep the bucket private.
   - Let CloudFront access it through an **Origin Access Control** (OAC).

Upload a placeholder `index.html` for now.

### 4.2 CloudFront distribution for `travel.your-domain.com`

1. Go to **CloudFront** → **Create distribution**.
2. **Origin**:
   - Origin type: **S3**.
   - Choose the bucket `travel.your-domain.com`.
3. **Viewer protocol policy**: Redirect HTTP to HTTPS.
4. **Alternate domain names (CNAMEs)**:
   - `travel.your-domain.com`
5. **Custom SSL certificate**: choose the ACM cert from step 3.
6. Create distribution and note the **Distribution ID** and **Domain name**.

### 4.3 Route 53 alias record for `travel`

1. Go to **Route 53 → Hosted zones → your-domain.com**.
2. Click **Create record**.
3. Name: `travel`.
4. Type: **A**.
5. Alias: **Yes**.
6. Alias target: the CloudFront distribution from 4.2.
7. Save.

After DNS propagates, `https://travel.your-domain.com` should show your S3 content.

---

## 5. Agent metadata: S3 + CloudFront

### 5.1 S3 bucket for agent metadata

1. Create S3 bucket `agent.your-domain.com` in `us-east-1`.
2. Same origin-access pattern as the travel bucket.

### 5.2 CloudFront distribution for `agent`

1. Create a new CloudFront distribution.
2. Origin: `agent.your-domain.com` bucket.
3. Alternate domain name: `agent.your-domain.com`.
4. SSL certificate: same ACM cert.
5. Note the **Distribution ID**.

### 5.3 Route 53 alias for `agent`

Create an **A (alias)** record:

- Name: `agent`
- Alias → CloudFront distribution

### 5.4 Agent keys JSON

In bucket `agent.your-domain.com`, create:

- Folder: `.well-known/http-message-signatures/`
- File: `keys.json`

Example (for the HMAC MVP):

```json
{
  "keys": [
    {
      "kty": "oct",
      "kid": "hap-demo-hmac",
      "alg": "HS256",
      "k": "base64url-encoded-secret-or-placeholder"
    }
  ]
}
```

The actual secret is configured in Lambda via `AGENT_SHARED_SECRET` and in the Colab client. This file is there to mirror the future “real” key registry spec.

Verify you can hit:

`https://agent.your-domain.com/.well-known/http-message-signatures/keys.json`

---

## 6. DynamoDB tables

Region: **us-east-1**.

### 6.1 `hap_stats` – traffic counts

- Table name: `hap_stats`
- Partition key: `day` (String), e.g. `2025-11-29`
- Sort key: `kind` (String): `"human" | "agent" | "unknown"`

### 6.2 `HAP_AGENT_WALLETS` – agent credits

- Table name: `HAP_AGENT_WALLETS`
- Partition key: `agentId` (String)
- Attributes: `credits` (Number), `updatedAt` (String ISO8601)

### 6.3 `HAP_PAYMENT_SESSIONS` – Stripe top‑ups

- Table name: `HAP_PAYMENT_SESSIONS`
- Partition key: `sessionId` (String)
- Attributes: `agentId`, `createdAt`, `paidAt`, `creditsPurchased`, `status`, optional `mode`.

---

## 7. Lambda functions

### 7.1 `hap-travel-api` Lambda

- Handles:
  - `GET /api/flights/search`
  - `GET /api/stats/summary`
  - `GET /api/billing/agents`
- Classifies requests into human / agent / unknown.
- Enforces agent HMAC signature and credits.

Permissions: allow `GetItem`, `PutItem`, `UpdateItem` on the three Dynamo tables; CloudWatch logs.

Environment variables (examples):

- `AGENT_SHARED_SECRET`
- `HAP_STATS_TABLE = hap_stats`
- `AGENT_WALLETS_TABLE = HAP_AGENT_WALLETS`
- `PAYMENT_SESSIONS_TABLE = HAP_PAYMENT_SESSIONS`
- `STRIPE_SECRET_KEY`
- `STRIPE_PRICE_ID`
- `STRIPE_PUBLIC_KEY`
- `STRIPE_SUCCESS_URL`
- `STRIPE_CANCEL_URL`

Code & deployment: see `lambda/hap-travel-api/` and section 10.

### 7.2 `hap-stripe-webhook` Lambda

- Handles `POST /api/payments/stripe-webhook`.
- Processes Checkout webhooks and credits agents.

Environment variables:

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `AGENT_WALLETS_TABLE = HAP_AGENT_WALLETS`
- `PAYMENT_SESSIONS_TABLE = HAP_PAYMENT_SESSIONS`

---

## 8. API Gateway (HTTP API)

Create HTTP API `hap-travel-api-http` and attach routes:

- `GET /api/flights/search` → `hap-travel-api`
- `GET /api/stats/summary` → `hap-travel-api`
- `GET /api/billing/agents` → `hap-travel-api`
- `POST /api/payments/stripe-webhook` → `hap-stripe-webhook`

Create custom domain `api.your-domain.com` with ACM cert and map it to this HTTP API.  
Create Route 53 **A (alias)** record `api` → API Gateway custom domain.

---

## 9. Stripe configuration

### 9.1 Product and price

- Product: “HAP Flight Search Credits”.
- One‑time price: `$1.00`, e.g. 100 credits.

### 9.2 API keys

From Stripe **Developers → API keys**:

- Secret key → `STRIPE_SECRET_KEY`
- Publishable key → `STRIPE_PUBLIC_KEY`

### 9.3 Webhook endpoint

- URL: `https://api.your-domain.com/api/payments/stripe-webhook`
- Events: `checkout.session.completed`
- Signing secret → `STRIPE_WEBHOOK_SECRET` in webhook Lambda.

---

## 10. Project layout & deploy script

The Git repo layout:

```text
hap-mvp-http-agent-profile/
  docs/
    setup-aws.md
  config/
    env.example
  lambda/
    hap-travel-api/
      lambda_function.py
      requirements.txt
      build.sh
    hap-stripe-webhook/
      lambda_function.py
      requirements.txt
      build.sh
  ui/
    travel/
      index.html
      dashboard.html
      dashboard.js
      styles.css
  agent/
    .well-known/http-message-signatures/keys.json
  scripts/
    deploy-all.sh
```

Each Lambda `build.sh` script:

- Installs dependencies into a `build/` directory.
- Zips the contents into `hap-travel-api.zip` or `hap-stripe-webhook.zip`.

The root script `scripts/deploy-all.sh`:

- Builds both Lambdas.
- Updates Lambda code in AWS.
- Syncs UI & agent S3 buckets.
- Invalidates CloudFront distributions.

Usage:

```bash
./scripts/deploy-all.sh
```

---

## 11. Colab agent client (high level)

The Colab agent:

- Signs requests with HAP‑style HMAC using `AGENT_SHARED_SECRET`.
- Sends:
  - `Sec-Client-Class: agent`
  - `Signature-Agent: https://agent.your-domain.com`
  - `Authorization: HAP-Sig <signature>`
- On 402:
  - Follows the returned `checkoutUrl` (Stripe Checkout).
- After payment:
  - Webhook updates wallet.
  - Next call gets 200 with flights and `creditsRemaining`.

This guide + the repo is enough for someone to recreate the MVP in a fresh AWS account.
