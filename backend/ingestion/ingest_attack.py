"""CLI script to ingest MITRE ATT&CK data into Qdrant.

Usage: python -m backend.ingestion.ingest_attack
"""

import time

from backend.ingestion.mitre_loader import (
    download_attack_data,
    extract_groups,
    extract_mitigations,
    extract_relationships,
    extract_software,
    extract_techniques,
)
from backend.rag.chunker import (
    chunk_groups,
    chunk_mitigations,
    chunk_relationships,
    chunk_software,
    chunk_techniques,
)
from backend.rag.embedder import encode_texts
from backend.rag.qdrant_store import get_qdrant_client, recreate_collection, upsert_chunks


def _embed_and_upsert(client, chunks: list[dict], batch_size: int = 32) -> None:
    """Embed chunks in batches and upsert to Qdrant."""
    total_batches = (len(chunks) + batch_size - 1) // batch_size
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i : i + batch_size]
        texts = [c["text"] for c in batch]

        t0 = time.time()
        embeddings = encode_texts(texts)
        elapsed = time.time() - t0

        upsert_chunks(client, batch, embeddings)
        print(
            f"  Batch {i // batch_size + 1}/{total_batches} ({len(batch)} chunks, {elapsed:.1f}s)"
        )


def main():
    print("=" * 60)
    print("MITRE ATT&CK Ingestion Pipeline (Extended)")
    print("=" * 60)

    # Step 1: Download STIX data
    print("\n[1/6] Downloading ATT&CK STIX data...")
    download_attack_data()

    # Step 2: Extract all entity types
    print("\n[2/6] Extracting entities...")
    techniques = extract_techniques()
    mitigations = extract_mitigations()
    software = extract_software()
    groups = extract_groups()
    relationships, id_lookup = extract_relationships()

    # Step 3: Chunk all entities
    print("\n[3/6] Chunking entities...")
    all_chunks: list[dict] = []

    technique_chunks = chunk_techniques(techniques)
    all_chunks.extend(technique_chunks)
    print(f"  Techniques: {len(technique_chunks)} chunks")

    mitigation_chunks = chunk_mitigations(mitigations)
    all_chunks.extend(mitigation_chunks)
    print(f"  Mitigations: {len(mitigation_chunks)} chunks")

    software_chunks = chunk_software(software)
    all_chunks.extend(software_chunks)
    print(f"  Software: {len(software_chunks)} chunks")

    group_chunks = chunk_groups(groups)
    all_chunks.extend(group_chunks)
    print(f"  Groups: {len(group_chunks)} chunks")

    relationship_chunks = chunk_relationships(relationships, id_lookup)
    all_chunks.extend(relationship_chunks)
    print(f"  Relationships: {len(relationship_chunks)} chunks")

    print(f"  Total: {len(all_chunks)} chunks")

    # Step 4: Recreate Qdrant collection (clean slate)
    print("\n[4/6] Recreating Qdrant collection...")
    client = get_qdrant_client()
    recreate_collection(client)

    # Step 5: Embed and upsert all chunks
    print("\n[5/6] Embedding and upserting to Qdrant...")
    _embed_and_upsert(client, all_chunks)

    # Step 6: Summary
    print("\n[6/6] Summary")
    print(f"  Techniques:    {len(technique_chunks)}")
    print(f"  Mitigations:   {len(mitigation_chunks)}")
    print(f"  Software:      {len(software_chunks)}")
    print(f"  Groups:        {len(group_chunks)}")
    print(f"  Relationships: {len(relationship_chunks)}")
    print(f"  Total ingested: {len(all_chunks)} chunks")
    print("\nDone!")


if __name__ == "__main__":
    main()
