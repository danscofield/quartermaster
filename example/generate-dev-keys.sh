#!/bin/bash
# Generate development keys for local Quartermaster deployment
set -e

DIR="$(cd "$(dirname "$0")" && pwd)/keys"
mkdir -p "$DIR"

echo "Generating signing key (ES256)..."
openssl ecparam -genkey -name prime256v1 -noout -out "$DIR/signing.pem" 2>/dev/null

echo "Generating CA key and certificate..."
openssl ecparam -genkey -name prime256v1 -noout -out "$DIR/ca.key.pem" 2>/dev/null
openssl req -new -x509 -key "$DIR/ca.key.pem" -out "$DIR/ca.cert.pem" \
  -days 365 -subj "/CN=Quartermaster Dev CA" 2>/dev/null

echo "Generating SPIRE trust bundle (dev JWKS)..."
# Extract the public key from the signing key and format as JWKS
# For local dev, we use the signing key as the SPIRE trust bundle
PUB_KEY=$(openssl ec -in "$DIR/signing.pem" -pubout 2>/dev/null)
cat > "$DIR/spire-jwks.json" <<EOF
{
  "keys": []
}
EOF

echo ""
echo "Keys generated in $DIR/"
echo "  signing.pem       — JWT signing key"
echo "  ca.key.pem        — CA private key"
echo "  ca.cert.pem       — CA certificate"
echo "  spire-jwks.json   — Empty SPIRE trust bundle (add keys for local testing)"
echo ""
echo "Run Quartermaster with:"
echo "  QM_CONFIG_PATH=./example/config.toml cargo run"
