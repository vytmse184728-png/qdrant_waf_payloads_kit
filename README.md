# Qdrant WAF Payloads Kit

Local Qdrant setup for building a reusable payload knowledge base for WAF / HTTP request analysis.

This project ingests payload lists from sources such as PayloadsAllTheThings or SecLists, stores them in a Qdrant collection named `waf_payloads`, and validates the full backup flow with snapshot export and restore.

## What it does

- Runs Qdrant locally with Docker
- Ingests payloads incrementally instead of embedding everything at once
- Stores payload metadata in a RAG-friendly format
- Creates collection snapshots for backup and migration
- Verifies restore on a separate test instance

## Collection

Main collection:

- `waf_payloads`

Example payload schema:

```json
{
  "text": "Attack Type: SQL Injection | Payload: ' OR 1=1--",
  "category": "SQLi",
  "raw_payload": "' OR 1=1--",
  "source": "PayloadsAllTheThings",
  "source_path": "SQL Injection/Intruder/sqli.txt",
  "source_line": 42
}
````

## Requirements

* Python 3.11+
* Docker Desktop
* PowerShell or any terminal that can run Docker and Python

## Install

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r .\requirements.txt
```

## Run Qdrant

```powershell
docker compose up -d
Invoke-RestMethod http://127.0.0.1:6335
```

## Dry run

Preview the first candidate files without ingesting:

```powershell
python .\scripts\ingest_payloads_incremental.py `
  --repo-root "C:\path\to\PayloadsAllTheThings" `
  --source-type payloadallthethings `
  --dry-run `
  --max-files 5
```

## Ingest

Ingest the first 5 files into `waf_payloads`:

```powershell
python .\scripts\ingest_payloads_incremental.py `
  --repo-root "C:\path\to\PayloadsAllTheThings" `
  --source-type payloadallthethings `
  --collection-name waf_payloads `
  --qdrant-url http://127.0.0.1:6335 `
  --max-files 5
```

Check point count:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:6335/collections/waf_payloads/points/count `
  -ContentType "application/json" `
  -Body '{"exact": true}'
```

## Create snapshot

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:6335/collections/waf_payloads/snapshots
Invoke-RestMethod http://127.0.0.1:6335/collections/waf_payloads/snapshots | ConvertTo-Json -Depth 8
```

## Export snapshot

```powershell
mkdir .\exported_snapshots -Force
docker exec qdrant sh -lc "ls -lah /qdrant/snapshots/waf_payloads"
docker cp qdrant:/qdrant/snapshots/waf_payloads/<snapshot-name>.snapshot .\exported_snapshots\
```