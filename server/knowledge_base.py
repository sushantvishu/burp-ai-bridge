import json
import re
from pathlib import Path

from server.rag_engine import KBIndex

BASE_DIR = Path(__file__).resolve().parent
KB_DIR = BASE_DIR / "kb"
RAG_DIR = BASE_DIR / "rag"
MEMORY_DIR = BASE_DIR / "memory"


def ensure_storage() -> None:
    KB_DIR.mkdir(parents=True, exist_ok=True)
    RAG_DIR.mkdir(parents=True, exist_ok=True)
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "note"


def write_note(title: str, content: str, source: str = "", tags: list[str] | None = None) -> Path:
    ensure_storage()
    safe_name = slugify(title)
    note_path = KB_DIR / f"{safe_name}.md"

    frontmatter = [
        f"Title: {title.strip()}",
        f"Source: {source.strip() or 'manual'}",
        f"Tags: {', '.join(tags or []) or 'general'}",
        "",
    ]
    note_path.write_text("\n".join(frontmatter) + content.strip() + "\n", encoding="utf-8")
    return note_path


def record_feedback(entry: dict) -> Path:
    ensure_storage()
    feedback_path = MEMORY_DIR / "feedback.jsonl"
    with feedback_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
    return feedback_path


def rebuild_index() -> dict:
    ensure_storage()
    index = KBIndex(kb_dir=KB_DIR, rag_dir=RAG_DIR)
    index.build_index()
    return {
        "kb_dir": str(KB_DIR),
        "rag_dir": str(RAG_DIR),
        "index_path": str(index.index_path),
        "documents": len(list(KB_DIR.glob("*.md"))),
        "chunks": len(index.chunks),
    }


def _note_metadata(note_path: Path) -> dict:
    title = note_path.stem
    source = ""
    tags: list[str] = []
    try:
        for line in note_path.read_text(encoding="utf-8", errors="ignore").splitlines()[:12]:
            stripped = line.strip()
            lowered = stripped.lower()
            if lowered.startswith("title:"):
                title = stripped.split(":", 1)[1].strip() or title
            elif lowered.startswith("source:"):
                source = stripped.split(":", 1)[1].strip()
            elif lowered.startswith("tags:"):
                tags = [item.strip() for item in stripped.split(":", 1)[1].split(",") if item.strip()]
    except OSError:
        pass
    return {
        "file": note_path.name,
        "title": title,
        "source": source,
        "tags": tags,
    }


def list_notes() -> list[dict]:
    ensure_storage()
    notes = []
    for note_path in sorted(KB_DIR.glob("*.md")):
        notes.append(_note_metadata(note_path))
    return notes


def search_notes_detailed(query: str, top_k: int = 3) -> dict:
    ensure_storage()
    index = KBIndex(kb_dir=KB_DIR, rag_dir=RAG_DIR)
    hits = index.search_hits(query, top_k=top_k)
    if not hits:
        return {
            "context": "No context found.",
            "hits": [],
        }

    metadata_cache = {item["file"]: item for item in list_notes()}
    detailed_hits = []
    for hit in hits:
        metadata = metadata_cache.get(hit["source"], {"file": hit["source"], "title": hit["source"], "source": "", "tags": []})
        detailed_hits.append({
            "file": metadata["file"],
            "title": metadata["title"],
            "source": metadata["source"],
            "tags": metadata["tags"],
            "score": hit["score"],
            "text": hit["text"],
            "chunk_id": hit["chunk_id"],
        })
    context = "\n\n".join(
        f"[Source: {item['file']} | Title: {item['title']} | Tags: {', '.join(item['tags']) or 'general'}]\n{item['text']}"
        for item in detailed_hits
    )
    return {
        "context": context,
        "hits": detailed_hits,
    }


def search_notes(query: str, top_k: int = 3) -> str:
    return search_notes_detailed(query, top_k=top_k)["context"]
