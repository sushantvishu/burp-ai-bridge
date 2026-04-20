from server.knowledge_base import search_notes_detailed


def search_local_knowledge(query: str, top_k: int = 3) -> dict:
    normalized = (query or "").strip()
    if not normalized:
        return {"context": "No context found.", "hits": []}
    return search_notes_detailed(normalized, top_k=top_k)
