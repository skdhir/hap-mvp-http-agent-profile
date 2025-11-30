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

# Track which step we're on so errors are easier to see
STEP="initialization"
trap 'echo ""; echo "❌ Deployment failed during: $STEP"; echo ""; exit 1' ERR

echo "🚀 Deploying HAP Travel – environment: $ENVIRONMENT"
echo "   AWS_PROFILE=${AWS_PROFILE:-default}, AWS_REGION=${AWS_REGION:-default}"
echo ""
echo "   TRAVEL_BUCKET     = $TRAVEL_BUCKET"
echo "   AGENT_BUCKET      = $AGENT_BUCKET"
echo "   TRAVEL_LAMBDA     = $TRAVEL_LAMBDA_NAME"
echo "   WEBHOOK_LAMBDA    = $WEBHOOK_LAMBDA_NAME"
echo "   AGENT_LAMBDA      = $AGENT_LAMBDA_NAME"
echo "   TRAVEL_CF_ID      = $TRAVEL_CF_ID"
echo "   AGENT_CF_ID       = $AGENT_CF_ID"
echo ""

########################################
# 2. Build and deploy Lambdas          #
########################################

# --- hap-travel-api ---

STEP="build $TRAVEL_LAMBDA_NAME"
echo "🚀 === $STEP ==="
pushd "$ROOT_DIR/lambda/hap-travel-api" > /dev/null
# Hide noisy build stdout, but keep errors on stderr visible
./build.sh > /dev/null
popd > /dev/null
echo "   ✅ Build complete"

STEP="deploy $TRAVEL_LAMBDA_NAME"
echo "🚀 === $STEP ==="
aws lambda update-function-code \
  --function-name "$TRAVEL_LAMBDA_NAME" \
  --zip-file fileb://"$ROOT_DIR/lambda/hap-travel-api/hap-travel-api.zip" \
  > /dev/null
echo "   ✅ Lambda code updated"
echo ""

# --- hap-stripe-webhook ---

STEP="build $WEBHOOK_LAMBDA_NAME"
echo "🚀 === $STEP ==="
pushd "$ROOT_DIR/lambda/hap-stripe-webhook" > /dev/null
./build.sh > /dev/null
popd > /dev/null
echo "   ✅ Build complete"

STEP="deploy $WEBHOOK_LAMBDA_NAME"
echo "🚀 === $STEP ==="
aws lambda update-function-code \
  --function-name "$WEBHOOK_LAMBDA_NAME" \
  --zip-file fileb://"$ROOT_DIR/lambda/hap-stripe-webhook/hap-stripe-webhook.zip" \
  > /dev/null
echo "   ✅ Lambda code updated"
echo ""

# --- hap-agents-api ---

STEP="build $AGENT_LAMBDA_NAME"
echo "🚀 === $STEP ==="
pushd "$ROOT_DIR/lambda/hap-agents-api" > /dev/null
./build.sh > /dev/null
popd > /dev/null
echo "   ✅ Build complete"

STEP="deploy $AGENT_LAMBDA_NAME"
echo "🚀 === $STEP ==="
aws lambda update-function-code \
  --function-name "$AGENT_LAMBDA_NAME" \
  --zip-file fileb://"$ROOT_DIR/lambda/hap-agents-api/hap-agents-api.zip" \
  > /dev/null
echo "   ✅ Lambda code updated"
echo ""

########################################
# 3. Sync static sites to S3           #
########################################

STEP="sync UI to S3 bucket $TRAVEL_BUCKET"
echo "🚀 === $STEP ==="
aws s3 sync "$ROOT_DIR/ui/travel" "s3://$TRAVEL_BUCKET" --delete > /dev/null
echo "   ✅ UI synced to S3"
echo ""

STEP="sync agent metadata to S3 bucket $AGENT_BUCKET"
echo "🚀 === $STEP ==="
aws s3 sync "$ROOT_DIR/agent" "s3://$AGENT_BUCKET" --delete > /dev/null
echo "   ✅ Agent metadata synced to S3"
echo ""

########################################
# 4. Invalidate CloudFront caches      #
########################################

STEP="invalidate CloudFront travel ($TRAVEL_CF_ID)"
echo "🚀 === $STEP ==="
aws cloudfront create-invalidation \
  --distribution-id "$TRAVEL_CF_ID" \
  --paths "/*" > /dev/null
echo "   ✅ CloudFront invalidation requested for travel"
echo ""

STEP="invalidate CloudFront agent ($AGENT_CF_ID)"
echo "🚀 === $STEP ==="
aws cloudfront create-invalidation \
  --distribution-id "$AGENT_CF_ID" \
  --paths "/*" > /dev/null
echo "   ✅ CloudFront invalidation requested for agent"
echo ""

echo "✅ Deployment complete."
