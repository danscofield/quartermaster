#!/bin/bash
# Generate development keys for local Quartermaster deployment
set -e

DIR="$(cd "$(dirname "$0")" && pwd)/keys"
mkdir -p "$DIR"

echo "Generating signing key (ES256, PKCS#8)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/signing.pem" 2>/dev/null

echo "Generating CA key and certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/ca.key.pem" 2>/dev/null
openssl req -new -x509 -key "$DIR/ca.key.pem" -out "$DIR/ca.cert.pem" \
  -days 365 -subj "/CN=Quartermaster Dev CA" 2>/dev/null

echo ""
echo "Keys generated in $DIR/"
echo "  signing.pem       — JWT signing key (PKCS#8)"
echo "  ca.key.pem        — CA private key (PKCS#8)"
echo "  ca.cert.pem       — CA certificate"
echo ""
echo "Run Quartermaster with:"
echo "  QM_CONFIG_PATH=./example/config.toml cargo run"
