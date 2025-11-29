#!/usr/bin/env bash
set -euo pipefail

# Disable AWS CLI pager so script doesn't get stuck
export AWS_PAGER=""

# Resolve repo root regardless of where we run from
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

########################################
# 1. Load environment config           #
########################################

ENVIRONMENT=${1:-dev}  # default env is "dev"
ENV_FILE="$ROOT_DIR/config/env.${ENVIRONMENT}.sh"

if [ ! -f "$ENV_FILE" ]; then
  echo "❌ Env file not found: $ENV_FILE"
  echo "   Create it from: config/env.example.sh"
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

# Optionally set AWS_REGION/AWS_PROFILE for aws CLI
if [ -n "${AWS_REGION:-}" ]; then
  export AWS_REGION
fi
if [ -n "${AWS_PROFILE:-}" ]; then
  export AWS_PROFILE
fi

echo "🚀 Deploying environment: $ENVIRONMENT"
echo "   AWS_PROFILE=${AWS_PROFILE:-default}, AWS_REGION=${AWS_REGION:-default}"

########################################
# 2. Build and deploy Lambdas          #
########################################

echo "=== Building and deploying $TRAVEL_LAMBDA_NAME ==="
pushd "$ROOT_DIR/lambda/hap-travel-api" > /dev/null
./build.sh
aws lambda update-function-code \
  --function-name "$TRAVEL_LAMBDA_NAME" \
  --zip-file fileb://hap-travel-api.zip
popd > /dev/null

echo "=== Building and deploying $WEBHOOK_LAMBDA_NAME ==="
pushd "$ROOT_DIR/lambda/hap-stripe-webhook" > /dev/null
./build.sh
aws lambda update-function-code \
  --function-name "$WEBHOOK_LAMBDA_NAME" \
  --zip-file fileb://hap-stripe-webhook.zip
popd > /dev/null

echo "=== Building and deploying $AGENT_LAMBDA_NAME ==="
pushd "$ROOT_DIR/lambda/hap-agents-api" > /dev/null
./build.sh
aws lambda update-function-code \
  --function-name "$AGENT_LAMBDA_NAME" \
  --zip-file fileb://hap-agents-api.zip
popd > /dev/null

########################################
# 3. Sync static sites to S3           #
########################################

echo "=== Syncing UI to S3 bucket: $TRAVEL_BUCKET ==="
aws s3 sync "$ROOT_DIR/ui/travel" "s3://$TRAVEL_BUCKET" --delete

echo "=== Syncing agent metadata to S3 bucket: $AGENT_BUCKET ==="
aws s3 sync "$ROOT_DIR/agent" "s3://$AGENT_BUCKET" --delete

########################################
# 4. Invalidate CloudFront caches      #
########################################

echo "=== Invalidating CloudFront cache for travel ($TRAVEL_CF_ID) ==="
aws cloudfront create-invalidation \
  --distribution-id "$TRAVEL_CF_ID" \
  --paths "/*" > /dev/null

echo "=== Invalidating CloudFront cache for agent ($AGENT_CF_ID) ==="
aws cloudfront create-invalidation \
  --distribution-id "$AGENT_CF_ID" \
  --paths "/*" > /dev/null

echo "✅ Deployment complete."
