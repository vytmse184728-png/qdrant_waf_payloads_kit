#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

import requests
from qdrant_client import QdrantClient
from qdrant_client.http import models
from sentence_transformers import SentenceTransformer

TEXT_EXTENSIONS = {
    ".txt",
    ".lst",
    ".list",
    ".payload",
    ".payloads",
    ".csv",
    ".md",
}

DEFAULT_INCLUDE_PATTERNS = {
    "payloadallthethings": [
        "**/Intruder/**/*.txt",
        "**/Intruder/**/*.lst",
        "**/Intruder/**/*.list",
        "**/Intruder/**/*.csv",
        "**/*payload*.txt",
    ],
    "seclists": [
        "Fuzzing/**/*.txt",
        "Fuzzing/**/*.lst",
        "Payloads/**/*.txt",
        "Web-Shells/**/*.txt",
    ],
}

DEFAULT_EXCLUDE_PATTERNS = [
    "**/.git/**",
    "**/Images/**",
    "**/*.png",
    "**/*.jpg",
    "**/*.jpeg",
    "**/*.gif",
    "**/*.svg",
    "**/*.pdf",
    "**/*.zip",
    "**/*.7z",
    "**/*.bin",
    "**/*.exe",
    "**/*.dll",
    "**/*.so",
]

CATEGORY_PATTERNS = [
    (re.compile(r"sql|sqli|injection/sql", re.I), "SQL Injection"),
    (re.compile(r"xss|cross.?site", re.I), "XSS"),
    (re.compile(r"ssti|template", re.I), "SSTI"),
    (re.compile(r"ssrf", re.I), "SSRF"),
    (re.compile(r"xxe|xml", re.I), "XXE"),
    (re.compile(r"lfi|local.?file", re.I), "LFI"),
    (re.compile(r"rfi|remote.?file", re.I), "RFI"),
    (re.compile(r"traversal|path", re.I), "Path Traversal"),
    (re.compile(r"command|cmdi|rce|exec", re.I), "Command Injection / RCE"),
    (re.compile(r"redirect", re.I), "Open Redirect"),
    (re.compile(r"crlf|header", re.I), "CRLF Injection"),
    (re.compile(r"ldap", re.I), "LDAP Injection"),
    (re.compile(r"xpath", re.I), "XPath Injection"),
    (re.compile(r"nosql", re.I), "NoSQL Injection"),
    (re.compile(r"graphql", re.I), "GraphQL"),
    (re.compile(r"smuggl", re.I), "HTTP Request Smuggling"),
    (re.compile(r"upload", re.I), "File Upload"),
    (re.compile(r"deserial", re.I), "Deserialization"),
]

SKIP_LINE_PATTERNS = [
    re.compile(r"^\s*$"),
    re.compile(r"^\s*#"),
    re.compile(r"^\s*//"),
    re.compile(r"^\s*/\*"),
    re.compile(r"^\s*\*\s*$"),
    re.compile(r"^\s*<!--"),
    re.compile(r"^\s*```"),
    re.compile(r"^\s*---+\s*$"),
    re.compile(r"^\s*==+\s*$"),
    re.compile(r"^\s*\|.*\|\s*$"),
    re.compile(r"^\s*<\/?[a-zA-Z][^>]*>\s*$"),
    re.compile(r"^\s*[-*+]\s+$"),
    re.compile(r"^\s*Note:\s*", re.I),
    re.compile(r"^\s*Description:\s*", re.I),
]


@dataclass
class PayloadRecord:
    file_path: Path
    relative_path: str
    source: str
    category: str
    line_no: int
    raw_payload: str
    text: str
    point_id: str


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def human_bytes(value: int | None) -> str:
    if value is None:
        return ""
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{value} B"


def infer_category(relative_path: str) -> str:
    for pattern, label in CATEGORY_PATTERNS:
        if pattern.search(relative_path):
            return label
    return "Generic Payload"


def clean_payload(line: str) -> str:
    line = line.replace("\u200b", "").replace("\ufeff", "")
    line = line.strip()
    line = re.sub(r"\s+", " ", line)
    return line


def looks_like_payload(line: str) -> bool:
    if any(pattern.search(line) for pattern in SKIP_LINE_PATTERNS):
        return False
    stripped = line.strip()
    if len(stripped) < 2:
        return False
    if len(stripped) > 4000:
        return False
    if stripped.lower().startswith(("title:", "author:", "license:", "tags:")):
        return False
    return True


def parse_text_file(path: Path) -> Iterator[tuple[int, str]]:
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for idx, raw_line in enumerate(fh, start=1):
            line = clean_payload(raw_line)
            if looks_like_payload(line):
                yield idx, line


def parse_markdown_codefences(path: Path) -> Iterator[tuple[int, str]]:
    in_code_fence = False
    code_lines: list[tuple[int, str]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for idx, raw_line in enumerate(fh, start=1):
            line = raw_line.rstrip("\n")
            if line.strip().startswith("```"):
                if in_code_fence:
                    for code_idx, code_line in code_lines:
                        payload = clean_payload(code_line)
                        if looks_like_payload(payload):
                            yield code_idx, payload
                    code_lines = []
                    in_code_fence = False
                else:
                    in_code_fence = True
                continue
            if in_code_fence:
                code_lines.append((idx, line))


def file_should_be_excluded(relative_path: str, exclude_patterns: list[str]) -> bool:
    path_obj = Path(relative_path)
    return any(path_obj.match(pattern) for pattern in exclude_patterns)


def discover_files(
    repo_root: Path,
    source_type: str,
    include_patterns: list[str],
    exclude_patterns: list[str],
    extract_readme_codefences: bool,
) -> list[Path]:
    candidates: set[Path] = set()
    for pattern in include_patterns:
        candidates.update(repo_root.glob(pattern))
    if extract_readme_codefences:
        candidates.update(repo_root.glob("**/README.md"))
    files = []
    for path in sorted(candidates):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        if file_should_be_excluded(rel, exclude_patterns):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name != "README.md":
            continue
        files.append(path)
    return files


def build_point_id(source: str, rel_path: str, line_no: int, raw_payload: str) -> str:
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, source)
    return str(uuid.uuid5(namespace, f"{rel_path}:{line_no}:{raw_payload}"))


def build_payload_record(path: Path, repo_root: Path, source: str, line_no: int, raw_payload: str) -> PayloadRecord:
    relative_path = path.relative_to(repo_root).as_posix()
    category = infer_category(relative_path)
    text = f"Attack Type: {category} | Payload: {raw_payload}"
    point_id = build_point_id(source, relative_path, line_no, raw_payload)
    return PayloadRecord(
        file_path=path,
        relative_path=relative_path,
        source=source,
        category=category,
        line_no=line_no,
        raw_payload=raw_payload,
        text=text,
        point_id=point_id,
    )


def iter_payload_records(
    path: Path,
    repo_root: Path,
    source: str,
    extract_readme_codefences: bool,
) -> Iterator[PayloadRecord]:
    if path.name == "README.md":
        if not extract_readme_codefences:
            return
        parser = parse_markdown_codefences(path)
    else:
        parser = parse_text_file(path)
    for line_no, raw_payload in parser:
        yield build_payload_record(path, repo_root, source, line_no, raw_payload)


def load_completed_map(state_dir: Path) -> dict[str, dict]:
    path = state_dir / "completed_files.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_completed_map(state_dir: Path, completed: dict[str, dict]) -> None:
    path = state_dir / "completed_files.json"
    path.write_text(json.dumps(completed, indent=2, ensure_ascii=False), encoding="utf-8")


def ensure_csv(state_dir: Path) -> Path:
    path = state_dir / "progress.csv"
    if not path.exists():
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                [
                    "timestamp",
                    "source",
                    "relative_path",
                    "file_sha256",
                    "records_added",
                    "collection_points_total",
                    "snapshot_name",
                    "snapshot_size_bytes",
                    "snapshot_size_human",
                    "snapshot_delta_bytes",
                    "storage_size_bytes",
                    "storage_size_human",
                    "storage_delta_bytes",
                    "elapsed_seconds",
                    "status",
                    "error",
                ]
            )
    return path


def append_progress_row(state_dir: Path, row: list[object]) -> None:
    path = ensure_csv(state_dir)
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(row)


def disk_usage_bytes(path: Path | None) -> int | None:
    if path is None:
        return None
    if not path.exists():
        return None
    try:
        output = subprocess.check_output(["du", "-sb", str(path)], text=True)
        return int(output.split()[0])
    except Exception:
        return None


def wait_for_snapshot_file(snapshot_path: Path, timeout_seconds: int = 60) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if snapshot_path.exists() and snapshot_path.stat().st_size > 0:
            return True
        time.sleep(0.5)
    return snapshot_path.exists()


def create_collection_snapshot(qdrant_url: str, collection_name: str) -> str:
    response = requests.post(f"{qdrant_url}/collections/{collection_name}/snapshots", timeout=300)
    response.raise_for_status()
    data = response.json()
    return data["result"]["name"]


def ensure_collection(client: QdrantClient, collection_name: str, vector_size: int) -> None:
    if not client.collection_exists(collection_name):
        client.create_collection(
            collection_name=collection_name,
            vectors_config=models.VectorParams(size=vector_size, distance=models.Distance.COSINE),
            on_disk_payload=True,
        )
        for field_name in ["category", "source", "source_path"]:
            try:
                client.create_payload_index(
                    collection_name=collection_name,
                    field_name=field_name,
                    field_schema=models.KeywordIndexParams(type="keyword", on_disk=True),
                )
            except Exception:
                pass


def count_points(client: QdrantClient, collection_name: str) -> int:
    try:
        result = client.count(collection_name=collection_name, exact=True)
        return int(result.count)
    except Exception:
        return -1


def chunked(items: list[PayloadRecord], size: int) -> Iterator[list[PayloadRecord]]:
    for idx in range(0, len(items), size):
        yield items[idx : idx + size]


def embed_records(model: SentenceTransformer, records: list[PayloadRecord]) -> list[list[float]]:
    texts = [record.text for record in records]
    embeddings = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return [list(map(float, vector)) for vector in embeddings]


def upsert_records(
    client: QdrantClient,
    collection_name: str,
    records: list[PayloadRecord],
    embeddings: list[list[float]],
) -> None:
    points = []
    for record, vector in zip(records, embeddings):
        points.append(
            models.PointStruct(
                id=record.point_id,
                vector=vector,
                payload={
                    "text": record.text,
                    "category": record.category,
                    "raw_payload": record.raw_payload,
                    "source": record.source,
                    "source_path": record.relative_path,
                    "source_line": record.line_no,
                    "payload_hash": sha256_text(record.raw_payload),
                },
            )
        )
    client.upsert(collection_name=collection_name, points=points, wait=True)


def source_name_from_type(source_type: str) -> str:
    if source_type == "payloadallthethings":
        return "PayloadsAllTheThings"
    if source_type == "seclists":
        return "SecLists"
    return "Custom"


def main() -> int:
    parser = argparse.ArgumentParser(description="Incrementally ingest payload files into Qdrant.")
    parser.add_argument("--repo-root", required=True, help="Local path to PayloadsAllTheThings or SecLists clone")
    parser.add_argument("--source-type", choices=["payloadallthethings", "seclists", "auto"], default="payloadallthethings")
    parser.add_argument("--qdrant-url", default="http://127.0.0.1:6333")
    parser.add_argument("--collection-name", default="waf_payloads")
    parser.add_argument("--model-name", default="sentence-transformers/all-MiniLM-L6-v2")
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--max-files", type=int, default=0, help="0 means no limit")
    parser.add_argument("--state-dir", default="./state/waf_payloads")
    parser.add_argument("--qdrant-storage-dir", default="", help="Optional host path to Qdrant storage for size measurements")
    parser.add_argument("--qdrant-snapshots-dir", default="", help="Optional host path to Qdrant snapshots for size measurements")
    parser.add_argument("--include", action="append", default=[], help="Additional glob patterns relative to repo root")
    parser.add_argument("--exclude", action="append", default=[], help="Additional exclude globs relative to repo root")
    parser.add_argument("--extract-readme-codefences", action="store_true")
    parser.add_argument("--snapshot-every-file", action="store_true")
    parser.add_argument("--snapshot-interval-files", type=int, default=0, help="Create a snapshot after every N successful files")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).expanduser().resolve()
    if not repo_root.exists():
        print(f"Repo root not found: {repo_root}", file=sys.stderr)
        return 2

    source_type = args.source_type
    if source_type == "auto":
        root_name = repo_root.name.lower()
        if "payloadsallthethings" in root_name:
            source_type = "payloadallthethings"
        elif "seclists" in root_name:
            source_type = "seclists"
        else:
            source_type = "payloadallthethings"

    state_dir = Path(args.state_dir).expanduser().resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    completed = load_completed_map(state_dir)

    include_patterns = list(DEFAULT_INCLUDE_PATTERNS.get(source_type, [])) + args.include
    exclude_patterns = DEFAULT_EXCLUDE_PATTERNS + args.exclude

    files = discover_files(
        repo_root=repo_root,
        source_type=source_type,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
        extract_readme_codefences=args.extract_readme_codefences,
    )
    if args.max_files > 0:
        files = files[: args.max_files]

    if not files:
        print("No candidate files found.", file=sys.stderr)
        return 1

    print(f"Discovered {len(files)} candidate files under {repo_root}")
    print(f"Source type: {source_type}")

    if args.dry_run:
        for path in files:
            print(path.relative_to(repo_root).as_posix())
        return 0

    model = SentenceTransformer(args.model_name)
    vector_size = int(model.get_sentence_embedding_dimension())

    client = QdrantClient(url=args.qdrant_url)
    ensure_collection(client, args.collection_name, vector_size)

    source_name = source_name_from_type(source_type)
    processed_files = 0
    storage_dir = Path(args.qdrant_storage_dir).expanduser().resolve() if args.qdrant_storage_dir else None
    snapshots_dir = Path(args.qdrant_snapshots_dir).expanduser().resolve() if args.qdrant_snapshots_dir else None
    previous_snapshot_size: int | None = None
    previous_storage_size: int | None = disk_usage_bytes(storage_dir)

    for file_index, path in enumerate(files, start=1):
        relative_path = path.relative_to(repo_root).as_posix()
        file_hash = sha256_file(path)
        completed_entry = completed.get(relative_path)
        if completed_entry and completed_entry.get("file_sha256") == file_hash and completed_entry.get("status") == "success":
            print(f"[SKIP] {relative_path} (already processed)")
            continue

        start_time = time.time()
        snapshot_name = ""
        snapshot_size = None
        snapshot_delta = None
        storage_size = None
        storage_delta = None
        try:
            records = list(iter_payload_records(path, repo_root, source_name, args.extract_readme_codefences))
            if not records:
                completed[relative_path] = {
                    "file_sha256": file_hash,
                    "status": "success",
                    "records_added": 0,
                    "timestamp": int(time.time()),
                }
                save_completed_map(state_dir, completed)
                append_progress_row(
                    state_dir,
                    [
                        int(time.time()),
                        source_name,
                        relative_path,
                        file_hash,
                        0,
                        count_points(client, args.collection_name),
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        round(time.time() - start_time, 3),
                        "success",
                        "",
                    ],
                )
                print(f"[EMPTY] {relative_path}")
                continue

            added_count = 0
            for batch in chunked(records, args.batch_size):
                embeddings = embed_records(model, batch)
                upsert_records(client, args.collection_name, batch, embeddings)
                added_count += len(batch)

            processed_files += 1
            should_snapshot = args.snapshot_every_file or (
                args.snapshot_interval_files > 0 and processed_files % args.snapshot_interval_files == 0
            )
            if should_snapshot:
                snapshot_name = create_collection_snapshot(args.qdrant_url, args.collection_name)
                if snapshots_dir is not None:
                    snapshot_path = snapshots_dir / args.collection_name / snapshot_name
                    if wait_for_snapshot_file(snapshot_path):
                        snapshot_size = snapshot_path.stat().st_size
                        snapshot_delta = snapshot_size - previous_snapshot_size if previous_snapshot_size is not None else None
                        previous_snapshot_size = snapshot_size
                storage_size = disk_usage_bytes(storage_dir)
                if storage_size is not None and previous_storage_size is not None:
                    storage_delta = storage_size - previous_storage_size
                previous_storage_size = storage_size if storage_size is not None else previous_storage_size

            total_points = count_points(client, args.collection_name)
            elapsed = round(time.time() - start_time, 3)
            completed[relative_path] = {
                "file_sha256": file_hash,
                "status": "success",
                "records_added": added_count,
                "timestamp": int(time.time()),
                "snapshot_name": snapshot_name,
                "snapshot_size_bytes": snapshot_size,
            }
            save_completed_map(state_dir, completed)
            append_progress_row(
                state_dir,
                [
                    int(time.time()),
                    source_name,
                    relative_path,
                    file_hash,
                    added_count,
                    total_points,
                    snapshot_name,
                    snapshot_size if snapshot_size is not None else "",
                    human_bytes(snapshot_size),
                    snapshot_delta if snapshot_delta is not None else "",
                    storage_size if storage_size is not None else "",
                    human_bytes(storage_size),
                    storage_delta if storage_delta is not None else "",
                    elapsed,
                    "success",
                    "",
                ],
            )
            print(
                f"[OK] {relative_path} | +{added_count} records | total={total_points}"
                + (f" | snapshot={snapshot_name} ({human_bytes(snapshot_size)})" if snapshot_name else "")
            )
        except Exception as exc:
            elapsed = round(time.time() - start_time, 3)
            completed[relative_path] = {
                "file_sha256": file_hash,
                "status": "failed",
                "error": str(exc),
                "timestamp": int(time.time()),
            }
            save_completed_map(state_dir, completed)
            append_progress_row(
                state_dir,
                [
                    int(time.time()),
                    source_name,
                    relative_path,
                    file_hash,
                    "",
                    count_points(client, args.collection_name),
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    elapsed,
                    "failed",
                    str(exc),
                ],
            )
            print(f"[ERR] {relative_path}: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
