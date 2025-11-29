#!/usr/bin/env bash
set -euo pipefail

rm -rf build
mkdir -p build

pip3 install -r requirements.txt -t build

cp lambda_function.py build/

cd build
zip -r ../hap-travel-api.zip .
cd ..

echo "Built hap-travel-api.zip"
