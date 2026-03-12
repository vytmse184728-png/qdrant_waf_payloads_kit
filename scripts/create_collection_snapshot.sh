#!/usr/bin/env bash
set -euo pipefail

QDRANT_URL="${QDRANT_URL:-http://127.0.0.1:6333}"
COLLECTION="${1:-waf_payloads}"

curl -fsS -X POST "${QDRANT_URL}/collections/${COLLECTION}/snapshots"
