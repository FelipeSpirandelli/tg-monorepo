#!/usr/bin/env python3
"""
test_search.py

Quick CLI to semantically search ingested PDF chunks in Qdrant and print matches.

Environment variables:
    QDRANT_URL (str): Qdrant URL, e.g., http://localhost:6333
    QDRANT_API_KEY (str|empty): optional API key
    QDRANT_COLLECTION (str): collection name, default 'pdf_rag'

Usage:
    python test_search.py --query "returns policy" --top-k 5
    python test_search.py --query "warranty terms" --doc-id "manual_v2" --top-k 8
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import List, Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels
from sentence_transformers import SentenceTransformer


@dataclass
class SearchHit:
    """Single search result with metadata.

    Attributes:
        doc_id: Document identifier used at ingestion time (often the pdf filename without extension).
        page: Zero-based page index of the chunk.
        score: Similarity score from Qdrant (higher is closer for cosine).
        text: Raw chunk text.
        source_path: Absolute path to the source PDF (if stored during ingestion).
    """

    doc_id: str
    page: int
    score: float
    text: str
    source_path: Optional[str]


def _build_filter(filter_doc_id: Optional[str]) -> Optional[qmodels.Filter]:
    """Build an optional Qdrant filter for doc_id.

    Args:
        filter_doc_id: If provided, restricts results to a single document.

    Returns:
        Qdrant Filter or None.
    """
    if not filter_doc_id:
        return None
    return qmodels.Filter(
        must=[
            qmodels.FieldCondition(
                key="doc_id", match=qmodels.MatchValue(value=filter_doc_id)
            )
        ]
    )


def search(
    query: str,
    top_k: int = 5,
    filter_doc_id: Optional[str] = None,
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
) -> List[SearchHit]:
    """Perform a semantic search against Qdrant for a query.

    Args:
        query: Free-text query.
        top_k: Number of results to return.
        filter_doc_id: Optional doc_id to restrict matches.
        model_name: Sentence-Transformers model (must match ingestion family).

    Returns:
        List of SearchHit results ordered by score (desc).
    """
    qdrant_url = os.getenv("QDRANT_URL", "http://localhost:6333")
    qdrant_api_key = os.getenv("QDRANT_API_KEY") or None
    collection = os.getenv("QDRANT_COLLECTION", "pdf_rag")

    model = SentenceTransformer(model_name)
    # Normalize = cosine-friendly parity with ingestion embeddings
    vector = model.encode([query], normalize_embeddings=True)[0].tolist()

    client = QdrantClient(url=qdrant_url, api_key=qdrant_api_key)
    qfilter = _build_filter(filter_doc_id)

    # with_payload ensures we get text / metadata back
    res = client.search(
        collection_name=collection,
        query_vector=vector,
        limit=top_k,
        with_payload=True,
        query_filter=qfilter,
    )

    hits: List[SearchHit] = []
    for r in res:
        payload = r.payload or {}
        hits.append(
            SearchHit(
                doc_id=str(payload.get("doc_id", "")),
                page=int(payload.get("page", 0)),
                score=float(r.score),
                text=str(payload.get("text", "")),
                source_path=payload.get("source_path"),
            )
        )
    return hits


def _print_results(query: str, hits: List[SearchHit]) -> None:
    """Pretty-print results with file path and page, plus a short snippet.

    Args:
        query: The query string used.
        hits: Results to print.
    """
    print(f"\nQuery: {query}")
    if not hits:
        print("No results.")
        return

    for i, h in enumerate(hits, 1):
        snippet = (h.text[:220] + "…") if len(h.text) > 220 else h.text
        src = h.source_path or "(unknown path)"
        # Page numbers shown as 1-based for humans
        print(
            f"\n[{i}] score={h.score:.4f}  doc_id='{h.doc_id}'  page={h.page + 1}\n"
            f"    file: {src}\n"
            f"    text: {snippet}"
        )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Search ingested PDFs in Qdrant.")
    parser.add_argument("--query", required=True, help="Free-text query to search")
    parser.add_argument("--top-k", type=int, default=5, help="Number of results")
    parser.add_argument("--doc-id", default=None, help="Optional doc_id filter")
    parser.add_argument(
        "--model",
        default="sentence-transformers/all-MiniLM-L6-v2",
        help="Sentence-Transformers model (must match ingestion family)",
    )
    args = parser.parse_args()

    hits = search(
        args.query, top_k=args.top_k, filter_doc_id=args.doc_id, model_name=args.model
    )
    _print_results(args.query, hits)


if __name__ == "__main__":
    main()
