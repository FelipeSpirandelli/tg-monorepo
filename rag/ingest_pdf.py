# ingest_pdfs.py
import glob
import os
import uuid
from dataclasses import dataclass
from typing import Iterable, List, Optional

from dotenv import load_dotenv
from pypdf import PdfReader
from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

load_dotenv()


@dataclass
class Chunk:
    """A text chunk ready for embedding and indexing.

    Attributes:
        doc_id: Stable identifier for the source document.
        page: 0-based page index within the document.
        chunk_id: Stable identifier for this chunk.
        text: The raw text of the chunk.
    """

    doc_id: str
    page: int
    chunk_id: str
    text: str


def read_pdf_text(pdf_path: str) -> List[str]:
    """Extract full text per page from a PDF.

    Args:
        pdf_path: Path to a PDF file.

    Returns:
        List of page strings, one entry per page.
    """
    reader = PdfReader(pdf_path)
    pages = []
    for page in reader.pages:
        pages.append(page.extract_text() or "")
    return pages


def chunk_text(text: str, chunk_size: int, overlap: int) -> List[str]:
    """Split text into overlapping chunks.

    Args:
        text: Input text to chunk.
        chunk_size: Target tokens/characters per chunk (approx chars here).
        overlap: Overlap size between consecutive chunks.

    Returns:
        List of chunk strings.
    """
    # Keep it char-based for simplicity; switch to tokenization if needed.
    text = " ".join(text.split())  # normalize whitespace
    if not text:
        return []
    chunks = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + chunk_size, n)
        chunks.append(text[start:end])
        if end == n:
            break
        start = end - overlap
        if start < 0:
            start = 0
    return chunks


def iter_pdf_chunks(
    pdf_path: str,
    chunk_size: int,
    overlap: int,
    doc_id: Optional[str] = None,
) -> Iterable[Chunk]:
    """Yield Chunk objects for all pages of a PDF.

    Args:
        pdf_path: Path to a PDF file.
        chunk_size: Chunk size in characters.
        overlap: Overlap in characters.
        doc_id: Optional predefined doc id; a uuid4 is used if None.

    Yields:
        Chunk objects with metadata and text.
    """
    _doc_id = doc_id or str(uuid.uuid4())
    pages = read_pdf_text(pdf_path)
    for page_idx, page_text in enumerate(pages):
        for i, text in enumerate(chunk_text(page_text, chunk_size, overlap)):
            yield Chunk(
                doc_id=_doc_id,
                page=page_idx,
                chunk_id=str(uuid.uuid4()),
                text=text,
            )


def ensure_collection(client: QdrantClient, collection: str, vector_size: int) -> None:
    """Create Qdrant collection if needed.

    Args:
        client: Qdrant client instance.
        collection: Target collection name.
        vector_size: Embedding dimension.
    """
    existing = [c.name for c in client.get_collections().collections]
    if collection in existing:
        return
    client.recreate_collection(
        collection_name=collection,
        vectors_config=qmodels.VectorParams(
            size=vector_size,
            distance=qmodels.Distance.COSINE,
        ),
    )


def embed_batches(
    model: SentenceTransformer,
    texts: List[str],
    batch_size: int = 64,
) -> List[List[float]]:
    """Compute embeddings in batches.

    Args:
        model: SentenceTransformer model.
        texts: List of texts to embed.
        batch_size: Batch size for inference.

    Returns:
        List of embeddings as float lists.
    """
    embs = []
    for i in range(0, len(texts), batch_size):
        embs.extend(
            model.encode(texts[i : i + batch_size], normalize_embeddings=True).tolist()
        )
    return embs


def main() -> None:
    """Batch-ingest PDFs from a directory into Qdrant.

    Loads configs from environment variables. It will:
    - Parse PDFs
    - Chunk text
    - Embed locally via Sentence-Transformers
    - Upsert into Qdrant with doc/page metadata
    """
    qdrant_url = os.getenv("QDRANT_URL", "http://localhost:6333")
    qdrant_api_key = os.getenv("QDRANT_API_KEY") or None
    collection = os.getenv("QDRANT_COLLECTION", "pdf_rag")

    input_dir = os.getenv("INGEST_INPUT_DIR", "./pdfs")
    chunk_size = int(os.getenv("CHUNK_SIZE", "800"))
    overlap = int(os.getenv("CHUNK_OVERLAP", "120"))

    # local, compact model
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    vector_size = model.get_sentence_embedding_dimension()

    client = QdrantClient(url=qdrant_url, api_key=qdrant_api_key)
    ensure_collection(client, collection, vector_size)

    pdf_files = sorted(glob.glob(os.path.join(input_dir, "**/*.pdf"), recursive=True))
    if not pdf_files:
        print(f"No PDFs found under: {input_dir}")
        return

    print(
        f"Found {len(pdf_files)} PDFs. Ingesting into '{collection}' on {qdrant_url} ..."
    )
    all_points = []
    for pdf_path in tqdm(pdf_files, desc="PDFs"):
        # Use filename as stable doc_id for easier filtering
        doc_id = os.path.splitext(os.path.basename(pdf_path))[0]
        chunks = list(iter_pdf_chunks(pdf_path, chunk_size, overlap, doc_id=doc_id))
        texts = [c.text for c in chunks]
        vectors = embed_batches(model, texts, batch_size=64)

        points = []
        for c, v in zip(chunks, vectors):
            points.append(
                qmodels.PointStruct(
                    id=c.chunk_id,
                    vector=v,
                    payload={
                        "doc_id": c.doc_id,
                        "page": c.page,
                        "text": c.text,
                        "source_path": os.path.abspath(pdf_path),
                    },
                )
            )
        # batch upserts per doc to keep memory bounded
        client.upsert(collection_name=collection, points=points)
        all_points.extend(points)

    print(f"Ingested {len(all_points)} chunks across {len(pdf_files)} PDFs.")


if __name__ == "__main__":
    print("Starting PDF ingestion...")
    main()
