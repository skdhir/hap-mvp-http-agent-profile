# Which AWS account/region/profile this env uses
export AWS_PROFILE="your-aws-profile-name"   # or leave empty to use default
export AWS_REGION="us-east-1"                # change per env

# Buckets for this environment
TRAVEL_BUCKET="travel.example.com"
AGENT_BUCKET="agent.example.com"

# Lambda names for this environment
TRAVEL_LAMBDA_NAME="hap-travel-api"
WEBHOOK_LAMBDA_NAME="hap-stripe-webhook"
AGENT_LAMBDA_NAME="hap-agents-api"

# CloudFront distributions for this environment
TRAVEL_CF_ID="E1E....L"
AGENT_CF_ID="E2...."

# hap-travel-api Lambda
AGENT_SHARED_SECRET=replace_me
HAP_STATS_TABLE=hap_stats
AGENT_WALLETS_TABLE=HAP_AGENT_WALLETS
PAYMENT_SESSIONS_TABLE=HAP_PAYMENT_SESSIONS

STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_PRICE_ID=price_xxx   # $1 = 100 credits
STRIPE_PUBLIC_KEY=pk_test_xxx

STRIPE_SUCCESS_URL=https://travel.sanatdhir.com/payment-success.html
STRIPE_CANCEL_URL=https://travel.sanatdhir.com/payment-cancel.html

# hap-stripe-webhook Lambda
STRIPE_WEBHOOK_SECRET=whsec_xxx
AGENT_WALLETS_TABLE=HAP_AGENT_WALLETS
PAYMENT_SESSIONS_TABLE=HAP_PAYMENT_SESSIONS
