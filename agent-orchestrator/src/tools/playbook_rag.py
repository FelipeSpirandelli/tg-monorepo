"""
playbook_rag.py

Tool for searching playbook knowledge from the RAG system using semantic search.
Integrates with the Qdrant vector database to find relevant playbook sections.
"""

import os
from dataclasses import dataclass
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels
from sentence_transformers import SentenceTransformer

from config import Config
from src.logger import logger


@dataclass
class PlaybookSearchResult:
    """Single playbook search result with metadata.

    Attributes:
        doc_id: Document identifier (playbook filename without extension).
        page: Zero-based page index of the chunk.
        score: Similarity score from Qdrant (higher is closer for cosine).
        text: Raw chunk text from the playbook.
        source_path: Absolute path to the source PDF (if stored during ingestion).
    """

    doc_id: str
    page: int
    score: float
    text: str
    source_path: str | None


def search_playbooks(
    query: str, top_k: int = 5, filter_doc_id: str | None = None, min_score: float = 0.3
) -> dict[str, Any]:
    """
    Perform semantic search against the playbook RAG system.

    Args:
        query: Natural language query to search for relevant playbook content
        top_k: Maximum number of results to return
        filter_doc_id: Optional specific playbook document to search within
        min_score: Minimum similarity score threshold (0.0 to 1.0)

    Returns:
        Dictionary containing search results and metadata
    """
    try:
        # Get configuration
        config = Config()

        logger.info(f"Searching playbooks with query: '{query}' in collection: {config.qdrant_collection}")

        # Initialize embedding model
        model = SentenceTransformer(config.embedding_model)
        vector = model.encode([query], normalize_embeddings=True)[0].tolist()

        # Initialize Qdrant client
        client = QdrantClient(url=config.qdrant_url, api_key=config.qdrant_api_key)

        # Build filter if specific document requested
        query_filter = None
        if filter_doc_id:
            query_filter = qmodels.Filter(
                must=[qmodels.FieldCondition(key="doc_id", match=qmodels.MatchValue(value=filter_doc_id))]
            )

        # Perform the search
        search_results = client.search(
            collection_name=config.qdrant_collection,
            query_vector=vector,
            limit=top_k,
            with_payload=True,
            query_filter=query_filter,
            score_threshold=min_score,
        )

        # Process results
        results = []
        for result in search_results:
            payload = result.payload or {}
            search_hit = PlaybookSearchResult(
                doc_id=str(payload.get("doc_id", "")),
                page=int(payload.get("page", 0)),
                score=float(result.score),
                text=str(payload.get("text", "")),
                source_path=payload.get("source_path"),
            )
            results.append(search_hit)

        # Format response
        response: dict[str, Any] = {
            "success": True,
            "query": query,
            "total_results": len(results),
            "results": [],
        }

        for i, hit in enumerate(results, 1):
            # Create a snippet for better readability
            snippet = hit.text[:300] + "..." if len(hit.text) > 300 else hit.text

            result_item = {
                "rank": i,
                "playbook": hit.doc_id,
                "page": hit.page + 1,  # Convert to 1-based for human readability
                "relevance_score": round(hit.score, 4),
                "snippet": snippet,
                "full_text": hit.text,
                "source_file": hit.source_path,
            }
            response["results"].append(result_item)

        logger.info(f"Found {len(results)} relevant playbook sections")
        return response

    except Exception as e:
        logger.error(f"Error searching playbooks: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "query": query,
            "total_results": 0,
            "results": [],
        }


def get_available_playbooks() -> dict[str, Any]:
    """
    Get list of available playbooks in the RAG system.

    Returns:
        Dictionary containing available playbook documents
    """
    try:
        # Get configuration
        config = Config()

        logger.info("Retrieving available playbooks from RAG system")

        # Initialize Qdrant client
        client = QdrantClient(url=config.qdrant_url, api_key=config.qdrant_api_key)

        # Get all points with just doc_id to find unique documents
        # This is a simple approach; for large collections, consider using scroll API
        scroll_result = client.scroll(
            collection_name=config.qdrant_collection,
            limit=1000,  # Adjust based on your collection size
            with_payload=["doc_id", "source_path"],
        )
        points = scroll_result[0] if scroll_result else []  # scroll returns (points, next_page_offset)

        # Extract unique documents
        unique_docs = {}
        for point in points:
            if not hasattr(point, "payload") or not point.payload:
                continue
            doc_id = point.payload.get("doc_id")
            source_path = point.payload.get("source_path")
            if doc_id and doc_id not in unique_docs:
                unique_docs[doc_id] = {
                    "doc_id": doc_id,
                    "source_path": source_path,
                    "filename": os.path.basename(source_path) if source_path else doc_id,
                }

        response = {
            "success": True,
            "total_playbooks": len(unique_docs),
            "playbooks": list(unique_docs.values()),
        }

        logger.info(f"Found {len(unique_docs)} playbooks in RAG system")
        return response

    except Exception as e:
        logger.error(f"Error retrieving available playbooks: {str(e)}")
        return {"success": False, "error": str(e), "total_playbooks": 0, "playbooks": []}


def search_playbook_by_topic(topic: str, top_k: int = 3) -> dict[str, Any]:
    """
    Search for playbooks related to a specific security topic or incident type.

    Args:
        topic: Security topic or incident type (e.g., "malware", "phishing", "data breach")
        top_k: Number of most relevant results to return

    Returns:
        Dictionary containing relevant playbook sections for the topic
    """
    # Enhance the query with security context
    enhanced_query = f"security incident response playbook procedures for {topic} attack threat"

    logger.info(f"Searching playbooks for security topic: {topic}")

    return search_playbooks(
        query=enhanced_query, top_k=top_k, min_score=0.25  # Lower threshold for topic searches
    )
