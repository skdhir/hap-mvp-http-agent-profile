#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAMBDA_DIR="$ROOT_DIR/lambda/hap-agents-api"
BUILD_DIR="$LAMBDA_DIR/build"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Install Python deps into build dir
pip install -r "$LAMBDA_DIR/requirements.txt" -t "$BUILD_DIR"

# Copy lambda code
cp "$LAMBDA_DIR/lambda_function.py" "$BUILD_DIR/"

# Zip it up
cd "$BUILD_DIR"
zip -r ../hap-agents-api.zip .
