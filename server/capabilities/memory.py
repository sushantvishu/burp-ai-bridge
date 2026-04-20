from server.memory_retrieval import (
    build_endpoint_fingerprint,
    describe_history_correlation,
    find_similar_history,
    summarize_similar_findings,
)


def build_history_fingerprint(payload_like, rule_context: dict) -> dict:
    return build_endpoint_fingerprint(payload_like, rule_context)


def find_history_matches(fingerprint: dict, limit: int = 5) -> list[dict]:
    return find_similar_history(fingerprint, limit=limit)


def describe_history_matches(fingerprint: dict, matches: list[dict]) -> list[str]:
    return describe_history_correlation(fingerprint, matches)


def summarize_history_matches(matches: list[dict]) -> dict:
    return summarize_similar_findings(matches)
