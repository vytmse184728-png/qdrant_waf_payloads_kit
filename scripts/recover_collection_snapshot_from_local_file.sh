#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <file_uri> [collection_name]" >&2
  echo "Example: $0 file:///qdrant/snapshots/waf_payloads/snapshot-2026-03-12.snapshot waf_payloads" >&2
  exit 1
fi

FILE_URI="$1"
COLLECTION="${2:-waf_payloads}"
QDRANT_URL="${QDRANT_URL:-http://127.0.0.1:6333}"

curl -fsS -X PUT \
  "${QDRANT_URL}/collections/${COLLECTION}/snapshots/recover" \
  -H 'Content-Type: application/json' \
  -d "{\"location\":\"${FILE_URI}\"}"
