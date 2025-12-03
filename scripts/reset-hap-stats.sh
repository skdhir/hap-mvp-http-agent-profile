# If you’re using AWS_PROFILE / AWS_REGION, export them as usual
export AWS_PROFILE=your-profile
export AWS_REGION=your-region

#!/usr/bin/env bash
set -euo pipefail

# Disable AWS CLI pager
export AWS_PAGER=""

TABLE_NAME=${1:-hap_stats}

echo "⚠️ This will DELETE and RECREATE the DynamoDB table: $TABLE_NAME"
read -p "Continue? (yes/no) " answer
if [ "$answer" != "yes" ]; then
  echo "Aborting."
  exit 1
fi

echo "🔨 Deleting table: $TABLE_NAME (if it exists)..."
if aws dynamodb describe-table --table-name "$TABLE_NAME" >/dev/null 2>&1; then
  aws dynamodb delete-table --table-name "$TABLE_NAME" >/dev/null
  echo "   Waiting for table deletion..."
  aws dynamodb wait table-not-exists --table-name "$TABLE_NAME"
  echo "   ✅ Table deleted"
else
  echo "   Table does not exist, skipping delete."
fi

echo "🧱 Creating table: $TABLE_NAME (day + kind)..."
aws dynamodb create-table \
  --table-name "$TABLE_NAME" \
  --attribute-definitions \
      AttributeName=day,AttributeType=S \
      AttributeName=kind,AttributeType=S \
  --key-schema \
      AttributeName=day,KeyType=HASH \
      AttributeName=kind,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  >/dev/null

echo "   Waiting for table to become ACTIVE..."
aws dynamodb wait table-exists --table-name "$TABLE_NAME"

echo "✅ $TABLE_NAME is ready and empty."
