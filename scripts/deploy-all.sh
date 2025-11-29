#!/usr/bin/env bash
set -euo pipefail

export AWS_PAGER=""

# Resolve repo root regardless of where we run from
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

########################################
# 1. Config – EDIT THESE FOR YOUR ENV  #
########################################

# S3 buckets
TRAVEL_BUCKET="travel.sanatdhir.com"
AGENT_BUCKET="agent.sanatdhir.com"

# Lambda function names (exactly as in AWS)
TRAVEL_LAMBDA_NAME="hap-travel-api"
WEBHOOK_LAMBDA_NAME="hap-stripe-webhook"
AGENT_LAMBDA_NAME="hap-agents-api"

# CloudFront Distribution IDs (from AWS console)
TRAVEL_CF_ID="E1G1WOJMP3K5UL"  # travel.sanatdhir.com distribution ID
AGENT_CF_ID="EHJVHXRVQ5BHQ"   # agent.sanatdhir.com distribution ID

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
