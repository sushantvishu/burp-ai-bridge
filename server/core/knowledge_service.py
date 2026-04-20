from server.knowledge_base import list_notes, search_notes_detailed


def query_local_knowledge(query: str, top_k: int = 5) -> dict:
    normalized_query = (query or "").strip()
    if not normalized_query:
        return {
            "query": "",
            "hits": [],
            "available_notes": list_notes(),
            "context": "No query supplied.",
        }

    result = search_notes_detailed(normalized_query, top_k=max(1, min(top_k, 10)))
    return {
        "query": normalized_query,
        "hits": result.get("hits", []),
        "available_notes": list_notes(),
        "context": result.get("context", "No context found."),
    }
