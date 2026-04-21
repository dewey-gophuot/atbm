#!/usr/bin/env bash
set -euo pipefail

BACKEND_URL="${1:-http://localhost:4321}"

echo "Backend: $BACKEND_URL"
read -r -s -p "Private key passphrase (Enter neu khoa demo fallback khong co passphrase): " PASSPHRASE
echo ""

curl -sS -X POST "$BACKEND_URL/admin/decrypt-all" \
  -H "Content-Type: application/json" \
  -d "{\"passphrase\":\"$PASSPHRASE\"}" | cat

echo ""
