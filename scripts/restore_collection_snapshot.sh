#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <snapshot_file> [collection_name]" >&2
  exit 1
fi

SNAPSHOT_FILE="$1"
COLLECTION="${2:-waf_payloads}"
QDRANT_URL="${QDRANT_URL:-http://127.0.0.1:6333}"

curl -fsS -X POST \
  "${QDRANT_URL}/collections/${COLLECTION}/snapshots/upload?priority=snapshot" \
  -H 'Content-Type: multipart/form-data' \
  -F "snapshot=@${SNAPSHOT_FILE}"
