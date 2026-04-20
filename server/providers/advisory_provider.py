from server.ai_client import analyze_traffic


def analyze_security_advisory(payload_like) -> dict:
    return analyze_traffic(payload_like)
