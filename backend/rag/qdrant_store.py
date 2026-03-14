"""Qdrant vector database client and collection management."""

import uuid
from functools import lru_cache

from qdrant_client import QdrantClient, models

from backend.config import get_settings

DENSE_DIM = 1024  # BGE-M3 output dimension


@lru_cache(maxsize=1)
def get_qdrant_client() -> QdrantClient:
    settings = get_settings()
    return QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)


def ensure_collection(client: QdrantClient | None = None) -> None:
    """Create the mitre_attack collection if it doesn't exist."""
    client = client or get_qdrant_client()
    settings = get_settings()
    collection = settings.qdrant_collection

    if client.collection_exists(collection):
        return

    client.create_collection(
        collection_name=collection,
        vectors_config={
            "dense": models.VectorParams(
                size=DENSE_DIM,
                distance=models.Distance.COSINE,
            )
        },
        sparse_vectors_config={
            "sparse": models.SparseVectorParams(index=models.SparseIndexParams(on_disk=False))
        },
    )
    print(f"Created Qdrant collection: {collection}")


def recreate_collection(client: QdrantClient | None = None) -> None:
    """Drop and recreate the mitre_attack collection for clean re-ingestion."""
    client = client or get_qdrant_client()
    settings = get_settings()
    collection = settings.qdrant_collection

    if client.collection_exists(collection):
        client.delete_collection(collection)
        print(f"Deleted existing Qdrant collection: {collection}")

    client.create_collection(
        collection_name=collection,
        vectors_config={
            "dense": models.VectorParams(
                size=DENSE_DIM,
                distance=models.Distance.COSINE,
            )
        },
        sparse_vectors_config={
            "sparse": models.SparseVectorParams(index=models.SparseIndexParams(on_disk=False))
        },
    )
    print(f"Created Qdrant collection: {collection}")


def upsert_chunks(
    client: QdrantClient,
    chunks: list[dict],
    embeddings,
) -> None:
    """Upsert embedded chunks into Qdrant.

    Each chunk must have at least: text, chunk_type.
    All other keys in the chunk dict are stored as payload metadata.
    Embeddings is an EmbeddingResult or has .dense_vecs and .sparse_weights.
    """
    settings = get_settings()

    points = []
    for i, chunk in enumerate(chunks):
        dense_vec = embeddings.dense_vecs[i].tolist()
        sparse = embeddings.sparse_weights[i]

        sparse_indices = [int(k) for k in sparse.keys()]
        sparse_values = [float(v) for v in sparse.values()]

        # Store all chunk fields as payload (text is always included)
        payload = {k: v for k, v in chunk.items()}

        point = models.PointStruct(
            id=str(uuid.uuid4()),
            vector={
                "dense": dense_vec,
                "sparse": models.SparseVector(
                    indices=sparse_indices,
                    values=sparse_values,
                ),
            },
            payload=payload,
        )
        points.append(point)

    client.upsert(collection_name=settings.qdrant_collection, points=points)
