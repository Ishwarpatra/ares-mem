"""
memory_store.py — The Semantic Memory Store of ARES-Mem.

Manages ChromaDB collections with strict ACL-based retrieval:
  - Primary collection: 'ares_memory'      (privilege level 3–5)
  - Quarantine collection: 'ares_quarantine' (privilege level 1–2)

5-Tier Privilege ACL:
  SYSTEM(5) > HIGH(4) > MEDIUM(3) > LOW(2) > UNTRUSTED(1)

Sandboxed Retrieval:
  The query is intercepted and filtered by the requesting task's minimum
  required privilege. Memories below the minimum are silently excluded
  from the context window and counted as quarantined retrievals.
"""
import os
import time
import logging
import uuid
import json
import chromadb
from src.circuit_breaker import chroma_circuit_breaker
from typing import Dict, Any, List, Optional, Tuple, cast

from models import PRIVILEGE_LEVELS, MIN_PRIVILEGE_FOR_TASK


# ── Reverse map: int → label ─────────────────────────────────────────────────
_PRIV_INT_TO_LABEL: Dict[int, str] = {v: k for k, v in PRIVILEGE_LEVELS.items()}


class MemoryStore:
    """
    The Semantic Memory Store (ChromaDB-backed).

    Manages two collections:
    1. `ares_memory`      — validated memories (privilege ≥ 3 / MEDIUM+)
    2. `ares_quarantine`  — flagged/untrusted memories (privilege < 3)

    ACL retrieval filters by minimum privilege level required for the
    requesting task type, preventing low-trust data from entering the
    decision-making context window.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        path: str = "./chroma_data",
    ):
        # Prefer HTTP client (Docker) over local persistent client
        chroma_host = host or os.getenv("CHROMA_HOST")
        chroma_port = port or int(os.getenv("CHROMA_PORT", "8000"))

        if chroma_host:
            self.client = chromadb.HttpClient(host=chroma_host, port=chroma_port)
            self._mode = "http"
        else:
            self.client = chromadb.PersistentClient(path=path)
            self._mode = "persistent"

        # Initialize collections
        self.collection = self.client.get_or_create_collection(
            name="ares_memory",
            metadata={"description": "Validated episodic traces — MEDIUM+ privilege"}
        )
        self.quarantine = self.client.get_or_create_collection(
            name="ares_quarantine",
            metadata={"description": "Flagged/untrusted traces — LOW/UNTRUSTED"}
        )
        self.escalations = self.client.get_or_create_collection(
            name="ares_escalations",
            metadata={"description": "Durable registry for escalation review tickets"}
        )
        self.audit_events = self.client.get_or_create_collection(
            name="audit_events",
            metadata={"description": "Immutable append-only audit trail"}
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Write Operations
    # ══════════════════════════════════════════════════════════════════════════

    def add_memory(self, validated_trace: Dict[str, Any]) -> str:
        """
        Adds a validated trace to ChromaDB (legacy API — backwards compatible).
        Routes to the appropriate collection based on trust_tier string.

        NOTE: This API stores metadata with a ``trust_tier`` string key.
        Memories stored here are NOT retrievable via ``retrieve_by_privilege()``
        (which filters on integer ``privilege_level``). Use ``add_memory_with_quarantine``
        for all new code paths.

        Returns the generated document ID.
        """
        trust_tier = validated_trace.get("trust_tier", "untrusted_external")
        tier_to_priv = {
            "verified_internal": 4,
            "medium_internal":   3,
            "untrusted_external": 1,
        }
        privilege_level = tier_to_priv.get(trust_tier, 1)

        provenance_tag = {
            "trust_tier":       trust_tier,
            "privilege_level":  privilege_level,
            "privilege_label":  _PRIV_INT_TO_LABEL.get(privilege_level, "untrusted"),
            "entropy":          validated_trace.get("features", {}).get("entropy", 0.0),
            "semantic_distance": validated_trace.get("features", {}).get("semantic_distance", 0.0),
            "origin_source":    "external",
            "quarantine":       privilege_level < 3,
        }

        doc_id = f"mem-{os.urandom(8).hex()}"
        self._route_to_collection(
            text=validated_trace["text"],
            provenance_tag=provenance_tag,
            doc_id=doc_id,
        )
        return doc_id

    def add_memory_with_quarantine(self, validated_result: Dict[str, Any]) -> Tuple[str, str]:
        """
        Adds a validated trace from validate_and_tag() to the correct collection.

        Args:
            validated_result: Output from MemoryGuard.validate_and_tag()

        Returns:
            Tuple of (doc_id, collection_name)
        """
        provenance_tag = validated_result.get("provenance_tag", {})
        privilege_level = validated_result.get("privilege_level", 1)
        text = validated_result["text"]
        quarantine = validated_result.get("quarantine", privilege_level < 3)

        # Ensure all metadata values are ChromaDB-compatible (str/int/float/bool)
        safe_tag = {
            k: v for k, v in provenance_tag.items()
            if isinstance(v, (str, int, float, bool))
        }

        # Save security classification and string privilege level to metadata
        safe_tag["security_classification"] = validated_result.get("security_classification", "valid")
        safe_tag["privilege_level_str"] = validated_result.get("privilege_label", "untrusted")

        doc_id = f"mem-{int(time.time() * 1000) % 10_000_000:07d}-{os.urandom(4).hex()}"
        collection_name = self._route_to_collection(text, safe_tag, doc_id)
        return doc_id, collection_name

    # ══════════════════════════════════════════════════════════════════════════
    # Read Operations (ACL-Filtered)
    # ══════════════════════════════════════════════════════════════════════════

    def sandbox_retrieve(
        self,
        query: str,
        min_trust_tier: str = "verified_internal",
        n_results: int = 5,
    ) -> List[str]:
        """
        ACL-filtered retrieval using legacy trust_tier strings.
        Maintained for backwards compatibility.

        Maps tier strings to privilege integers and delegates to retrieve_by_privilege.
        """
        tier_to_priv = {
            "verified_internal":  4,
            "medium_internal":    3,
            "untrusted_external": 1,
        }
        min_priv = tier_to_priv.get(min_trust_tier, 4)
        allowed, _ = self.retrieve_by_privilege(query, min_privilege=min_priv, n_results=n_results)
        return allowed

    def retrieve_by_privilege(
        self,
        query: str,
        min_privilege: int = 3,
        task_type: Optional[str] = None,
        n_results: int = 5,
    ) -> Tuple[List[str], List[str]]:
        """
        Sandboxed retrieval with 5-tier ACL filtering.

        If `task_type` is provided, overrides `min_privilege` with the
        task's required sensitivity level from MIN_PRIVILEGE_FOR_TASK.

        Args:
            query:         Natural language query for semantic search.
            min_privilege: Minimum privilege level (1–5) for inclusion.
            task_type:     Optional task type key from TASK_SENSITIVITY.
            n_results:     Maximum results to return.

        Returns:
            Tuple of (allowed: List[str], quarantined: List[str])
        """
        if task_type and task_type in MIN_PRIVILEGE_FOR_TASK:
            min_privilege = MIN_PRIVILEGE_FOR_TASK[task_type]

        # Over-fetch to account for post-filter reduction
        fetch_n = max(n_results * 3, 15)

        # Check how many documents are in the collection
        collection_count = self.collection.count()
        if collection_count == 0:
            return [], []

        actual_n = min(fetch_n, collection_count)
        
        def _do_query():
            return self.collection.query(
                query_texts=[query],
                n_results=actual_n,
            )
            
        def _fallback():
            logger.warning("[MemoryStore] ChromaDB circuit OPEN. Returning empty results.")
            return {"documents": [], "metadatas": []}

        results = chroma_circuit_breaker.call(_do_query, _fallback)

        allowed: List[str] = []
        quarantined: List[str] = []

        docs_list = results.get("documents") if results is not None else None
        metas_list = results.get("metadatas") if results is not None else None
        
        docs = docs_list[0] if docs_list is not None and len(docs_list) > 0 else []
        metas = metas_list[0] if metas_list is not None and len(metas_list) > 0 else []

        for doc, meta in zip(docs, metas):
            if doc is None or meta is None:
                continue
            mem_priv_val = meta.get("privilege_level", 1)
            if isinstance(mem_priv_val, str):
                mem_priv = PRIVILEGE_LEVELS.get(mem_priv_val.lower(), 1)
            else:
                mem_priv = int(cast(Any, mem_priv_val))
                
            if mem_priv >= min_privilege:
                allowed.append(doc)
            else:
                quarantined.append(doc)

        return allowed[:n_results], quarantined

    def get_quarantine_summary(self) -> Dict[str, Any]:
        """
        Returns an audit summary of the quarantine collection.
        """
        count = self.quarantine.count()
        if count == 0:
            return {"count": 0, "samples": [], "message": "Quarantine collection is empty."}

        # Fetch up to 5 samples
        fetch_n = min(5, count)
        results = self.quarantine.get(
            limit=fetch_n,
            include=["documents", "metadatas"]
        )
        samples = []
        docs = results.get("documents") or []
        metas = results.get("metadatas") or []
        for doc, meta in zip(docs, metas):
            if doc is None or meta is None:
                continue
            samples.append({
                "text_preview": doc[:80] + "..." if len(doc) > 80 else doc,
                "privilege_label": meta.get("privilege_label", "untrusted"),
                "semantic_distance": meta.get("semantic_distance", "n/a"),
            })

        return {
            "count": count,
            "samples": samples,
            "message": f"{count} item(s) in quarantine collection."
        }

    def stats(self) -> Dict[str, int]:
        """Returns memory and quarantine collection sizes."""
        return {
            "memory_count":     self.collection.count(),
            "quarantine_count": self.quarantine.count(),
        }

    def get_all_memories(self, limit: int = 100) -> list:
        """Returns all stored memory entries for analytics / reporting."""
        result = self.collection.get(limit=limit)
        out = []
        for doc, meta in zip(result.get("documents") or [], result.get("metadatas") or []):
            out.append({"text": doc, **(meta or {})})
        return out

    # ══════════════════════════════════════════════════════════════════════════
    # Internal Helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _route_to_collection(
        self,
        text: str,
        provenance_tag: Dict[str, Any],
        doc_id: str,
    ) -> str:
        """Routes a memory to the correct collection based on privilege level."""
        privilege_level = int(provenance_tag.get("privilege_level", 1))
        quarantine_flag = bool(provenance_tag.get("quarantine", privilege_level < 3))

        target = self.quarantine if (quarantine_flag or privilege_level < 3) else self.collection
        collection_name = "ares_quarantine" if target is self.quarantine else "ares_memory"

        # ChromaDB raises an exception on duplicate IDs. The timestamp-modulo doc_id
        # wraps every ~2.8 hours; the 4-byte random suffix makes true collision
        # astronomically rare, but we retry once with a fresh random ID to be safe.
        try:
            target.add(
                documents=[text],
                metadatas=[provenance_tag],
                ids=[doc_id],
            )
        except Exception:
            fallback_id = f"mem-{os.urandom(8).hex()}"
            target.add(
                documents=[text],
                metadatas=[provenance_tag],
                ids=[fallback_id],
            )
        return collection_name
