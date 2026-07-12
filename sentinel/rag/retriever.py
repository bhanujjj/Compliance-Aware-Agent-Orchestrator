"""
RAG retriever — query string → top-k TechniqueMapping results.
Usage:
    from sentinel.rag.retriever import get_retriever
    retriever = get_retriever()
    results = retriever.query("SSH brute force login attempts", top_k=3)
"""
from pathlib import Path
from functools import lru_cache
import chromadb
from chromadb.utils import embedding_functions
from sentinel.models import TechniqueMapping

PROJECT_ROOT = Path(__file__).parent.parent.parent
CHROMA_PATH  = PROJECT_ROOT / "data" / "chroma_db"
COLLECTION   = "mitre_attack"

DEFAULT_EF   = embedding_functions.DefaultEmbeddingFunction()

class AttackRetriever:
    def __init__(self):
        self._col: chromadb.Collection | None = None

    def _load(self) -> chromadb.Collection:
        if self._col is None:
            if not CHROMA_PATH.exists():
                raise RuntimeError(
                    "ChromaDB index not found. Run first:\n"
                    "  python sentinel/rag/build_index.py"
                )
            client = chromadb.PersistentClient(path=str(CHROMA_PATH))
            self._col = client.get_collection(COLLECTION, embedding_function=DEFAULT_EF)
        return self._col

    def query(self, query_text: str, top_k: int = 3) -> list[TechniqueMapping]:
        """
        Query the index for the most relevant MITRE ATT&CK techniques.
        Args:
            query_text: Natural-language description of the incident/attack behaviour.
            top_k: Number of results to return.
        Returns:
            List of TechniqueMapping sorted by confidence (descending).
        """
        col = self._load()
        results = col.query(
            query_texts=[query_text],
            n_results=min(top_k, col.count()),
            include=["metadatas", "distances", "documents"],
        )

        mappings = []
        ids        = results["ids"][0]
        metadatas  = results["metadatas"][0]
        distances  = results["distances"][0]

        for tid, meta, dist in zip(ids, metadatas, distances):
            # ChromaDB cosine distance = 1 - cosine_similarity
            # So confidence (similarity) = 1 - dist, clamped to [0, 1]
            confidence = round(max(0.0, 1.0 - dist), 4)
            tid_clean = tid.split(".")[0]  # "T1110.001" → "T1110" for URL
            
            mappings.append(
                TechniqueMapping(
                    technique_id=tid,
                    technique_name=meta.get("name", ""),
                    tactic=meta.get("tactic", ""),
                    description=meta.get("description", "")[:200],
                    confidence=confidence,
                    mitre_url=meta.get("url", f"https://attack.mitre.org/techniques/{tid_clean}/"),
                )
            )

        # Sort by confidence descending (highest similarity first)
        mappings.sort(key=lambda m: m.confidence, reverse=True)
        return mappings

    def is_ready(self) -> bool:
        """Return True if the index exists and has documents."""
        try:
            col = self._load()
            return col.count() > 0
        except Exception:
            return False

@lru_cache(maxsize=1)
def get_retriever() -> AttackRetriever:
    """Return a singleton retriever instance (loaded once per process)."""
    return AttackRetriever()
