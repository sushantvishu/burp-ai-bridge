from copy import deepcopy

DEFAULT_PROFILE = "mcp-grounded-llama32"

LEGACY_PROFILE_ALIASES = {
    "bug-bounty-safe": "mcp-grounded-llama32",
    "api-review": "mcp-grounded-llama32",
    "high-impact-bounty": "deep-escalation-local-8b",
    "deep-escalation-llama32-7b": "deep-escalation-local-8b",
}

PROFILES = {
    "low-resource-local": {
        "name": "low-resource-local",
        "description": "Lean local mode that keeps prompts shorter and retrieval tighter for CPU-bound laptops.",
        "default_review_scope": [
            "access-control",
            "authentication",
            "csrf",
            "input-validation",
            "security-misconfiguration",
            "session-management",
            "sqli",
            "xss",
        ],
        "kb_top_k": 2,
        "memory_top_k": 2,
        "prefer_small_context": True,
        "recommended_model": "qwen3:1.7b",
        "best_for": "fast triage on CPU-bound laptops",
    },
    "mcp-grounded-llama32": {
        "name": "mcp-grounded-llama32",
        "description": "MCP-first local profile tuned for llama3.2:3b with heavier KB and memory grounding for Burp Scanner triage, safe escalation, and report-quality follow-up.",
        "default_review_scope": [
            "access-control",
            "authentication",
            "business-logic",
            "cors",
            "csrf",
            "deserialization",
            "file-upload",
            "graphql",
            "http-request-smuggling",
            "information-disclosure",
            "jwt-token",
            "mass-assignment",
            "path-traversal",
            "race-condition",
            "secret-exposure",
            "session-management",
            "sqli",
            "ssrf",
            "ssti",
            "xss",
            "xxe",
        ],
        "kb_top_k": 6,
        "memory_top_k": 5,
        "prefer_small_context": False,
        "recommended_model": "llama3.2:3b",
        "best_for": "balanced Burp MCP triage and escalation on local hardware",
    },
    "deep-escalation-local-8b": {
        "name": "deep-escalation-local-8b",
        "description": "Deeper local profile for an 8B-class local model focused on scanner-anchored escalation planning, evidence thresholds, and higher-quality bug bounty reporting.",
        "default_review_scope": [
            "access-control",
            "authentication",
            "business-logic",
            "command-injection",
            "cors",
            "csrf",
            "deserialization",
            "file-upload",
            "graphql",
            "http-request-smuggling",
            "information-disclosure",
            "jwt-token",
            "mass-assignment",
            "path-traversal",
            "race-condition",
            "secret-exposure",
            "session-management",
            "sqli",
            "ssrf",
            "ssti",
            "xss",
            "xxe"
        ],
        "kb_top_k": 7,
        "memory_top_k": 6,
        "prefer_small_context": False,
        "recommended_model": "llama3.1:latest",
        "best_for": "deeper escalation reasoning and report-quality output",
    },
}


def normalize_profile_name(profile_name: str | None) -> str:
    candidate = (profile_name or "").strip().lower()
    candidate = LEGACY_PROFILE_ALIASES.get(candidate, candidate)
    if candidate in PROFILES:
        return candidate
    return DEFAULT_PROFILE


def get_profile(profile_name: str | None) -> dict:
    return deepcopy(PROFILES[normalize_profile_name(profile_name)])


def list_profiles() -> list[dict]:
    return []
