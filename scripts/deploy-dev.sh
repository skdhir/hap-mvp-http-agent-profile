#!/usr/bin/env bash
set -euo pipefail

# Disable AWS CLI pager so script doesn't get stuck
export AWS_PAGER=""

# Resolve repo root regardless of where we run from
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

########################################
# 1. Load environment config           #
########################################

ENVIRONMENT=${1:-dev}          # first arg: env (dev/prod/etc.)
FORCE_BUILD_FLAG=${2:-""}      # second arg: "force" (optional)

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

# Should we force rebuilds?
FORCE_ALL_BUILDS=0
if [ "$FORCE_BUILD_FLAG" = "force" ]; then
  FORCE_ALL_BUILDS=1
fi

echo "🚀 Deploying HAP Travel – environment: $ENVIRONMENT"
echo "   AWS_PROFILE=${AWS_PROFILE:-default}, AWS_REGION=${AWS_REGION:-default}"
echo "   FORCE_ALL_BUILDS=${FORCE_ALL_BUILDS}"
echo "   TRAVEL_BUCKET     = $TRAVEL_BUCKET"
echo "   AGENT_BUCKET      = $AGENT_BUCKET"
echo "   TRAVEL_LAMBDA     = $TRAVEL_LAMBDA_NAME"
echo "   WEBHOOK_LAMBDA    = $WEBHOOK_LAMBDA_NAME"
echo "   AGENT_LAMBDA      = $AGENT_LAMBDA_NAME"
echo ""

##################################################
# Helper: build react/ts ui code if changed      #
##################################################

cd ui/agentpassport && npm install && npm run build

########################################
# Helper: build+deploy if changed      #
########################################

build_and_deploy_lambda_if_changed() {
  local label="$1"          # e.g. hap-travel-api
  local dir="$2"            # e.g. $ROOT_DIR/lambda/hap-travel-api
  local zip_name="$3"       # e.g. hap-travel-api.zip
  local function_name="$4"  # e.g. $TRAVEL_LAMBDA_NAME

  echo "=== Lambda: $function_name ($label) ==="
  local zip_path="$dir/$zip_name"

  local need_build=0

  if [ "$FORCE_ALL_BUILDS" -eq 1 ]; then
    echo "   Force flag set → build regardless of timestamps."
    need_build=1
  elif [ ! -f "$zip_path" ]; then
    echo "   No existing zip found → will build."
    need_build=1
  else
    # Any .py or requirements.txt newer than the zip?
    if find "$dir" \
        -type f \( -name '*.py' -o -name 'requirements.txt' -o -name 'build.sh' \) \
        -newer "$zip_path" | grep -q .; then
      echo "   Source changes detected → will build."
      need_build=1
    fi
  fi

  if [ "$need_build" -eq 1 ]; then
    echo "   Building package..."
    (cd "$dir" && ./build.sh > /dev/null)
    echo "   Deploying to Lambda..."
    aws lambda update-function-code \
      --function-name "$function_name" \
      --zip-file fileb://"$zip_path" \
      > /dev/null
    echo "   ✅ Built and deployed $function_name"
  else
    echo "   No code/requirements changes detected → skipping build & deploy."
  fi

  echo ""
}

########################################
# 2. Build and deploy Lambdas          #
########################################

build_and_deploy_lambda_if_changed \
  "hap-travel-api" \
  "$ROOT_DIR/lambda/hap-travel-api" \
  "hap-travel-api.zip" \
  "$TRAVEL_LAMBDA_NAME"

build_and_deploy_lambda_if_changed \
  "hap-stripe-webhook" \
  "$ROOT_DIR/lambda/hap-stripe-webhook" \
  "hap-stripe-webhook.zip" \
  "$WEBHOOK_LAMBDA_NAME"

build_and_deploy_lambda_if_changed \
  "hap-agents-api" \
  "$ROOT_DIR/lambda/hap-agents-api" \
  "hap-agents-api.zip" \
  "$AGENT_LAMBDA_NAME"

########################################
# 3. Sync static sites to S3           #
########################################

echo "=== Syncing UI to S3 bucket: $TRAVEL_BUCKET ==="
aws s3 sync "$ROOT_DIR/ui/travel" "s3://$TRAVEL_BUCKET" \
  --delete \
  --only-show-errors \
  --no-progress
echo "   ✅ UI sync complete"
echo ""

echo "=== Syncing agent metadata to S3 bucket: $AGENT_BUCKET ==="
aws s3 sync "$ROOT_DIR/agent" "s3://$AGENT_BUCKET" \
  --delete \
  --only-show-errors \
  --no-progress
echo "   ✅ Agent metadata sync complete"
echo ""

echo "=== Syncing React UI to S3 bucket: $TRAVEL_BUCKET/agentpassport ==="
aws s3 sync "$ROOT_DIR/ui/agentpassport/dist" "s3://$TRAVEL_BUCKET/agentpassport" \
  --delete \
  --only-show-errors \
  --no-progress
echo "   ✅ React UI sync complete"
echo ""

########################################
# 4. Invalidate CloudFront caches      #
########################################

echo "=== Invalidating CloudFront cache for travel ($TRAVEL_CF_ID) ==="
aws cloudfront create-invalidation \
  --distribution-id "$TRAVEL_CF_ID" \
  --paths "/*" \
  > /dev/null
echo "   ✅ Travel CloudFront invalidation requested"
echo ""

echo "=== Invalidating CloudFront cache for agent ($AGENT_CF_ID) ==="
aws cloudfront create-invalidation \
  --distribution-id "$AGENT_CF_ID" \
  --paths "/*" \
  > /dev/null
echo "   ✅ Agent CloudFront invalidation requested"
echo ""

echo "🎉 ✅ Deployment COMPLETE for environment: $ENVIRONMENT"
