import chromadb
from chromadb.config import Settings
import os

class MemoryStore:
    """
    The Semantic Memory Store: Manages isolated collections with strict ACL retrieval.
    """
    def __init__(self, host=None, port=None):
        if host and port:
            self.client = chromadb.HttpClient(host=host, port=port)
        else:
            self.client = chromadb.PersistentClient(path="./chroma_data")
        
        self.collection = self.client.get_or_create_collection(name="ares_memory")

    def add_memory(self, validated_trace):
        """Adds a validated trace to the vector database with metadata tags."""
        self.collection.add(
            documents=[validated_trace["text"]],
            metadatas=[{
                "trust_tier": validated_trace["trust_tier"],
                "entropy": validated_trace["features"]["entropy"],
                "semantic_distance": validated_trace["features"]["semantic_distance"]
            }],
            ids=[os.urandom(8).hex()]
        )

    def sandbox_retrieve(self, query, min_trust_tier="verified_internal", n_results=5):
        """
        Filters vector DB results based on trust tier.
        Tiers: verified_internal > medium_internal > untrusted_external
        """
        tier_hierarchy = {"verified_internal": 3, "medium_internal": 2, "untrusted_external": 1}
        min_score = tier_hierarchy.get(min_trust_tier, 3)
        
        # Over-fetch to filter
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results * 2
        )
        
        allowed = []
        for i, doc in enumerate(results["documents"][0]):
            meta = results["metadatas"][0][i]
            doc_score = tier_hierarchy.get(meta.get("trust_tier", "untrusted_external"), 1)
            
            if doc_score >= min_score:
                allowed.append(doc)
                
        return allowed[:n_results]
