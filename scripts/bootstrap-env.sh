#!/usr/bin/env bash
set -euo pipefail

# Disable AWS CLI pager
export AWS_PAGER=""

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ENVIRONMENT=${1:-dev}
ENV_FILE="$ROOT_DIR/config/env.${ENVIRONMENT}.sh"

if [ ! -f "$ENV_FILE" ]; then
  echo "❌ Env file not found: $ENV_FILE"
  echo "   Create it from: config/env.example.sh"
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

if [ -n "${AWS_REGION:-}" ]; then
  export AWS_REGION
fi
if [ -n "${AWS_PROFILE:-}" ]; then
  export AWS_PROFILE
fi

echo "🧱 Bootstrapping HAP env: $ENVIRONMENT"
echo "   AWS_PROFILE=${AWS_PROFILE:-default}, AWS_REGION=${AWS_REGION:-default}"
echo "   TRAVEL_BUCKET     = $TRAVEL_BUCKET"
echo "   AGENT_BUCKET      = $AGENT_BUCKET"
echo "   TRAVEL_LAMBDA     = $TRAVEL_LAMBDA_NAME"
echo "   WEBHOOK_LAMBDA    = $WEBHOOK_LAMBDA_NAME"
echo "   AGENT_LAMBDA      = $AGENT_LAMBDA_NAME"
echo ""

########################################
# Helpers                              #
########################################

ensure_s3_bucket() {
  local bucket="$1"
  echo "→ Ensuring S3 bucket: $bucket"

  if aws s3api head-bucket --bucket "$bucket" 2>/dev/null; then
    echo "   ✅ Bucket exists"
    return 0
  fi

  echo "   Creating bucket..."
  if [ "${AWS_REGION:-us-east-1}" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$bucket" \
      >/dev/null
  else
    aws s3api create-bucket --bucket "$bucket" \
      --create-bucket-configuration LocationConstraint="$AWS_REGION" \
      >/dev/null
  fi
  echo "   ✅ Bucket created"
}

ensure_dynamo_table_simple() {
  local table_name="$1"
  local hash_key="$2"
  local hash_type="$3"   # S, N, etc.

  echo "→ Ensuring DynamoDB table: $table_name"

  if aws dynamodb describe-table --table-name "$table_name" >/dev/null 2>&1; then
    echo "   ✅ Table exists"
    return 0
  fi

  echo "   Creating table..."
  aws dynamodb create-table \
    --table-name "$table_name" \
    --attribute-definitions AttributeName="$hash_key",AttributeType="$hash_type" \
    --key-schema AttributeName="$hash_key",KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    >/dev/null

  echo "   Waiting for table to become ACTIVE..."
  aws dynamodb wait table-exists --table-name "$table_name"
  echo "   ✅ Table created"
}

ensure_dynamo_table_hap_stats() {
  local table_name="$1"
  echo "→ Ensuring DynamoDB table (hap_stats): $table_name"

  if aws dynamodb describe-table --table-name "$table_name" >/dev/null 2>&1; then
    echo "   ✅ Table exists"
    return 0
  fi

  echo "   Creating hap_stats table (day + kind)..."
  aws dynamodb create-table \
    --table-name "$table_name" \
    --attribute-definitions \
        AttributeName=day,AttributeType=S \
        AttributeName=kind,AttributeType=S \
    --key-schema \
        AttributeName=day,KeyType=HASH \
        AttributeName=kind,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    >/dev/null

  echo "   Waiting for table to become ACTIVE..."
  aws dynamodb wait table-exists --table-name "$table_name"
  echo "   ✅ hap_stats table created"
}

########################################
# 1. Ensure S3 buckets                 #
########################################

ensure_s3_bucket "$TRAVEL_BUCKET"
ensure_s3_bucket "$AGENT_BUCKET"

########################################
# 2. Ensure DynamoDB tables            #
########################################

# Adjust names if your env file uses different variable names
ensure_dynamo_table_hap_stats "$HAP_STATS_TABLE"
ensure_dynamo_table_simple "$HAP_WALLETS_TABLE" "agentId" "S"
ensure_dynamo_table_simple "$PAYMENT_SESSIONS_TABLE" "sessionId" "S"
ensure_dynamo_table_simple "$HAP_AGENTS_TABLE" "agentId" "S"
ensure_dynamo_table_simple "$HAP_USERS_TABLE" "email" "S"

########################################
# 3. (Optional) Ensure Lambda stubs    #
########################################
# For now we assume Lambdas & API Gateway & CloudFront are created once
# via console and their names/IDs are put into env.${ENVIRONMENT}.sh.
# You *can* extend this script to:
#  - build Lambda zips
#  - aws lambda create-function ...
#  - configure API Gateway + CloudFront
# but that’s closer to full IaC (Terraform/CDK).
########################################

echo ""
echo "✅ Bootstrap complete for env: $ENVIRONMENT"
echo "   Next: ./scripts/deploy-all.sh $ENVIRONMENT"
