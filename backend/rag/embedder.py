"""BGE-M3 embedding model wrapper for dual dense+sparse encoding."""

from functools import lru_cache

from FlagEmbedding import BGEM3FlagModel


@lru_cache(maxsize=1)
def get_embedder() -> BGEM3FlagModel:
    """Load BGE-M3 model (cached singleton). ~2GB download on first call."""
    return BGEM3FlagModel("BAAI/bge-m3", use_fp16=True)


class EmbeddingResult:
    """Container for dual dense + sparse embeddings."""

    def __init__(self, dense_vecs: list, sparse_weights: list):
        self.dense_vecs = dense_vecs
        self.sparse_weights = sparse_weights


def encode_texts(texts: list[str]) -> EmbeddingResult:
    """Encode texts into both dense and sparse representations."""
    model = get_embedder()
    output = model.encode(texts, return_dense=True, return_sparse=True)
    return EmbeddingResult(
        dense_vecs=output["dense_vecs"],
        sparse_weights=output["lexical_weights"],
    )


def encode_query(query: str) -> EmbeddingResult:
    """Encode a single query into dense + sparse representations."""
    return encode_texts([query])
