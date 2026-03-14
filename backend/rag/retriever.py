"""Hybrid search retriever using Qdrant with Reciprocal Rank Fusion."""

from qdrant_client import QdrantClient, models

from backend.config import get_settings
from backend.rag.embedder import encode_query
from backend.rag.qdrant_store import get_qdrant_client


def hybrid_search(query: str, top_k: int = 5, client: QdrantClient | None = None) -> list[dict]:
    """Run hybrid dense+sparse search with RRF fusion over MITRE ATT&CK.

    Returns a list of dicts with: text, technique_id, name, tactics, score.
    """
    client = client or get_qdrant_client()
    settings = get_settings()

    emb = encode_query(query)
    dense_vec = emb.dense_vecs[0].tolist()
    sparse = emb.sparse_weights[0]

    sparse_indices = [int(k) for k in sparse.keys()]
    sparse_values = [float(v) for v in sparse.values()]

    results = client.query_points(
        collection_name=settings.qdrant_collection,
        prefetch=[
            models.Prefetch(query=dense_vec, using="dense", limit=top_k * 3),
            models.Prefetch(
                query=models.SparseVector(
                    indices=sparse_indices,
                    values=sparse_values,
                ),
                using="sparse",
                limit=top_k * 3,
            ),
        ],
        query=models.FusionQuery(fusion=models.Fusion.RRF),
        limit=top_k,
    )

    return [
        {
            "text": point.payload.get("text", ""),
            "technique_id": point.payload.get("technique_id", ""),
            "name": point.payload.get("name", ""),
            "tactics": point.payload.get("tactics", []),
            "score": point.score,
        }
        for point in results.points
    ]
