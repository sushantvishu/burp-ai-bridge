from server.rule_engine import build_rule_context


def build_deterministic_context(payload_like) -> dict:
    return build_rule_context(payload_like)
