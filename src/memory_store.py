import chromadb
import os

# Anchor ChromaDB storage relative to this file, not the working directory
_SRC_DIR  = os.path.dirname(os.path.abspath(__file__))
_CHROMA_PATH = os.path.join(_SRC_DIR, "chroma_data")

class MemoryStore:
    """
    The Semantic Memory Store: Manages isolated collections with strict ACL retrieval.

    Trust tiers (ordered high → low):
        verified_internal  (3) — clean internal traces
        medium_internal    (2) — external source, no adversarial signals
        untrusted_external (1) — one or more adversarial signals detected
    """

    _TIER_HIERARCHY = {
        "verified_internal":  3,
        "medium_internal":    2,
        "untrusted_external": 1,
    }

    def __init__(self, host: str = None, port: int = None):
        if host and port:
            self.client = chromadb.HttpClient(host=host, port=port)
        else:
            self.client = chromadb.PersistentClient(path=_CHROMA_PATH)

        self.collection = self.client.get_or_create_collection(name="ares_memory")

    def add_memory(self, validated_trace: dict):
        """Adds a validated trace to the vector database with full feature metadata."""
        features = validated_trace.get("features", {})
        self.collection.add(
            documents=[validated_trace["text"]],
            metadatas=[{
                "trust_tier":         validated_trace["trust_tier"],
                "entropy":            features.get("entropy", 0.0),
                "semantic_distance":  features.get("semantic_distance", 0.0),
                "imperative_density": features.get("imperative_density", 0.0),
            }],
            ids=[os.urandom(8).hex()]
        )

    def sandbox_retrieve(self, query: str, min_trust_tier: str = "verified_internal", n_results: int = 5) -> list:
        """
        Retrieves documents filtered by minimum trust tier.

        Only documents at or above `min_trust_tier` are returned.
        Over-fetches (2×) to account for post-filter reduction.
        """
        min_score = self._TIER_HIERARCHY.get(min_trust_tier, 3)

        # Guard against requesting more results than the collection has
        total_docs = self.collection.count()
        fetch_count = min(n_results * 2, max(total_docs, 1))

        results = self.collection.query(
            query_texts=[query],
            n_results=fetch_count
        )

        allowed = []
        for i, doc in enumerate(results["documents"][0]):
            meta = results["metadatas"][0][i]
            doc_score = self._TIER_HIERARCHY.get(
                meta.get("trust_tier", "untrusted_external"), 1
            )
            if doc_score >= min_score:
                allowed.append(doc)

        return allowed[:n_results]

    def get_all_memories(self, limit: int = 100) -> list:
        """Returns all stored memory entries for analytics / reporting."""
        result = self.collection.get(limit=limit)
        out = []
        for doc, meta in zip(result.get("documents") or [], result.get("metadatas") or []):
            out.append({"text": doc, **(meta or {})})
        return out
