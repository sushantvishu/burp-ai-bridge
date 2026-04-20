from server.core.whitebox_service import whitebox_enrichment


def build_whitebox_enrichment(query: str) -> dict:
    return whitebox_enrichment(query)
