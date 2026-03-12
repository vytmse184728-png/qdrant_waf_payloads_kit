from qdrant_client import QdrantClient, models

SRC_URL = "http://127.0.0.1:6333"
DST_URL = "http://127.0.0.1:6335" 
COLLECTION = "waf_payloads"
BATCH_SIZE = 256

src = QdrantClient(url=SRC_URL, timeout=60.0)
dst = QdrantClient(url=DST_URL, timeout=60.0)


def ensure_destination_collection():
    try:
        dst.get_collection(COLLECTION)
        print(f"[OK] destination collection '{COLLECTION}' already exists")
        return
    except Exception:
        pass

    print(f"[INFO] creating destination collection '{COLLECTION}'")
    dst.create_collection(
        collection_name=COLLECTION,
        vectors_config=models.VectorParams(
            size=384,
            distance=models.Distance.COSINE,
        ),
        on_disk_payload=True,
    )

    for field_name in ["category", "source", "source_path"]:
        print(f"[INFO] creating payload index for {field_name}")
        dst.create_payload_index(
            collection_name=COLLECTION,
            field_name=field_name,
            field_schema=models.PayloadSchemaType.KEYWORD,
        )


def get_count(client: QdrantClient, collection_name: str) -> int:
    return client.count(collection_name=collection_name, exact=True).count


def record_to_point(record):
    if record.vector is None:
        raise ValueError(f"Record {record.id} has no vector. Check scroll(..., with_vectors=True).")

    return models.PointStruct(
        id=record.id,
        vector=record.vector,
        payload=record.payload or {},
    )


def main():
    ensure_destination_collection()

    src_count_before = get_count(src, COLLECTION)
    dst_count_before = get_count(dst, COLLECTION)

    print(f"[INFO] source count before = {src_count_before}")
    print(f"[INFO] dest   count before = {dst_count_before}")

    offset = None
    total_migrated = 0
    batch_no = 0

    while True:
        records, next_offset = src.scroll(
            collection_name=COLLECTION,
            limit=BATCH_SIZE,
            offset=offset,
            with_payload=True,
            with_vectors=True,
        )

        if not records:
            break

        points = [record_to_point(r) for r in records]

        dst.upsert(
            collection_name=COLLECTION,
            points=points,
            wait=True,
        )

        batch_no += 1
        total_migrated += len(points)
        print(f"[INFO] batch={batch_no} migrated={total_migrated}")

        if next_offset is None:
            break

        offset = next_offset

    src_count_after = get_count(src, COLLECTION)
    dst_count_after = get_count(dst, COLLECTION)

    print(f"[DONE] source count after = {src_count_after}")
    print(f"[DONE] dest   count after = {dst_count_after}")

    if src_count_after == dst_count_after:
        print("[OK] migration count matches")
    else:
        print("[WARN] migration count mismatch")


if __name__ == "__main__":
    main()