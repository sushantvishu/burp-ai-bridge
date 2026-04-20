import os
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_MCP_DISABLED_BY_PARENT = os.environ.get("BURP_AI_BRIDGE_DISABLE_MCP", "").strip().lower() in {"1", "true", "yes", "on"}


def _env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_provider_order(raw: str) -> tuple[str, ...]:
    allowed = {"mcp", "ollama"}
    normalized: list[str] = []
    for item in (raw or "").split(","):
        name = item.strip().lower()
        if not name or name not in allowed:
            continue
        if name in normalized:
            continue
        normalized.append(name)
    return tuple(normalized)


OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate").strip()
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b").strip()
OLLAMA_FAST_MODEL = os.environ.get("OLLAMA_FAST_MODEL", "qwen3:1.7b").strip()
OLLAMA_DEEP_MODEL = os.environ.get("OLLAMA_DEEP_MODEL", "llama3.1:latest").strip()
OLLAMA_CODE_MODEL = os.environ.get("OLLAMA_CODE_MODEL", "llama3.2:3b").strip()
OLLAMA_VISION_MODEL = os.environ.get("OLLAMA_VISION_MODEL", "").strip()
OLLAMA_TIMEOUT_SECONDS = int(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "150"))
OLLAMA_VISION_TIMEOUT_SECONDS = int(os.environ.get("OLLAMA_VISION_TIMEOUT_SECONDS", str(OLLAMA_TIMEOUT_SECONDS)))
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "768"))
OLLAMA_NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "256"))
ENABLE_DIRECT_OLLAMA_FALLBACK = _env_flag("ENABLE_DIRECT_OLLAMA_FALLBACK", "true")
MCP_ENABLED = (
    _env_flag("MCP_ENABLED", "true")
    and not _MCP_DISABLED_BY_PARENT
)
MCP_TRANSPORT = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
MCP_SERVER_COMMAND = os.environ.get("MCP_SERVER_COMMAND", "python -m server.mcp_server.app").strip()
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "").strip()
MCP_WORKING_DIRECTORY = os.environ.get("MCP_WORKING_DIRECTORY", str(_PROJECT_ROOT)).strip()
MCP_TOOL_NAME = os.environ.get("MCP_TOOL_NAME", "analyze_security_exchange").strip()
MCP_TIMEOUT_SECONDS = int(os.environ.get("MCP_TIMEOUT_SECONDS", str(OLLAMA_TIMEOUT_SECONDS)))
MCP_PROTOCOL_VERSION = os.environ.get("MCP_PROTOCOL_VERSION", "2025-06-18").strip()
BURP_MCP_CONTEXT_ENABLED = _env_flag("BURP_MCP_CONTEXT_ENABLED", "true")
BURP_MCP_TRANSPORT = os.environ.get("BURP_MCP_TRANSPORT", "auto").strip().lower()
BURP_MCP_SERVER_URL = os.environ.get("BURP_MCP_SERVER_URL", "http://127.0.0.1:9876").strip()
BURP_MCP_PROXY_COMMAND = os.environ.get("BURP_MCP_PROXY_COMMAND", "").strip()
BURP_MCP_WORKING_DIRECTORY = os.environ.get("BURP_MCP_WORKING_DIRECTORY", str(_PROJECT_ROOT)).strip()
BURP_MCP_TIMEOUT_SECONDS = int(os.environ.get("BURP_MCP_TIMEOUT_SECONDS", "20"))
BURP_MCP_CONTEXT_HISTORY_LIMIT = int(os.environ.get("BURP_MCP_CONTEXT_HISTORY_LIMIT", "8"))
BURP_MCP_FETCH_SCANNER_ISSUES = _env_flag("BURP_MCP_FETCH_SCANNER_ISSUES", "true")
BURP_MCP_CACHE_TTL_SECONDS = int(os.environ.get("BURP_MCP_CACHE_TTL_SECONDS", "15"))
BURP_MCP_DEBOUNCE_WINDOW_MS = int(os.environ.get("BURP_MCP_DEBOUNCE_WINDOW_MS", "250"))
BURP_MCP_READ_ONLY_ONLY = _env_flag("BURP_MCP_READ_ONLY_ONLY", "true")
BURP_MCP_ALLOWED_TOOLS = tuple(
    item.strip()
    for item in os.environ.get("BURP_MCP_ALLOWED_TOOLS", "").split(",")
    if item.strip()
)
BURP_MCP_ALLOWED_CAPABILITIES = tuple(
    item.strip().lower()
    for item in os.environ.get("BURP_MCP_ALLOWED_CAPABILITIES", "").split(",")
    if item.strip()
)
INTERNET_REFERENCE_ENRICHMENT_ENABLED = _env_flag("INTERNET_REFERENCE_ENRICHMENT_ENABLED", "true")
INTERNET_REFERENCE_MODE = os.environ.get("INTERNET_REFERENCE_MODE", "curated-only").strip().lower()
AUTO_MODEL_ROUTING_ENABLED = _env_flag("AUTO_MODEL_ROUTING_ENABLED", "true")
MODEL_PROVIDER_ORDER = _normalize_provider_order(os.environ.get("MODEL_PROVIDER_ORDER", "mcp,ollama"))
MODEL_SCHEDULER_SEQUENTIAL_ONLY = _env_flag("MODEL_SCHEDULER_SEQUENTIAL_ONLY", "true")
MODEL_ROUTING_FAST_SCORE_THRESHOLD = int(os.environ.get("MODEL_ROUTING_FAST_SCORE_THRESHOLD", "1"))
MODEL_ROUTING_DEEP_SCORE_THRESHOLD = int(os.environ.get("MODEL_ROUTING_DEEP_SCORE_THRESHOLD", "8"))
MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT = int(os.environ.get("MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT", "4"))
EXECUTION_DEFAULT_RATE_LIMIT = int(os.environ.get("EXECUTION_DEFAULT_RATE_LIMIT", "5"))
EXECUTION_HARD_MAX_RATE_LIMIT = int(os.environ.get("EXECUTION_HARD_MAX_RATE_LIMIT", "10"))
EXECUTION_DEFAULT_MAX_CONCURRENCY = int(os.environ.get("EXECUTION_DEFAULT_MAX_CONCURRENCY", "1"))
EXECUTION_HARD_MAX_CONCURRENCY = int(os.environ.get("EXECUTION_HARD_MAX_CONCURRENCY", "5"))
EXECUTION_SCOPE_ENFORCEMENT_ENABLED = _env_flag("EXECUTION_SCOPE_ENFORCEMENT_ENABLED", "true")
EXECUTION_KILL_SWITCH = _env_flag("EXECUTION_KILL_SWITCH", "false")
DEFAULT_BOUNTY_PLATFORM = os.environ.get("DEFAULT_BOUNTY_PLATFORM", "generic").strip().lower()
BROWSER_VERIFICATION_REQUIRE_EXPLICIT_ALLOW = _env_flag("BROWSER_VERIFICATION_REQUIRE_EXPLICIT_ALLOW", "true")
WHITEBOX_MODE_ENABLED = _env_flag("WHITEBOX_MODE_ENABLED", "false")
WHITEBOX_ROOT = os.environ.get("WHITEBOX_ROOT", "").strip()
WHITEBOX_MAX_FILES = int(os.environ.get("WHITEBOX_MAX_FILES", "20"))
PRIVACY_MODE = os.environ.get("PRIVACY_MODE", "STRICT").strip().upper()
SKIP_MODEL_FOR_LOW_SIGNAL = _env_flag("SKIP_MODEL_FOR_LOW_SIGNAL", "true")
ANALYSIS_LOOP_ENABLED = _env_flag("ANALYSIS_LOOP_ENABLED", "true")
ANALYSIS_LOOP_MAX_STEPS = int(os.environ.get("ANALYSIS_LOOP_MAX_STEPS", "3"))
ANALYSIS_LOOP_SCANNER_MAX_STEPS = int(os.environ.get("ANALYSIS_LOOP_SCANNER_MAX_STEPS", "2"))
ANALYSIS_LOOP_HARD_STEP_CAP = int(os.environ.get("ANALYSIS_LOOP_HARD_STEP_CAP", "6"))
BCHECKS_SYNC_URL = os.environ.get(
    "BCHECKS_SYNC_URL",
    "https://codeload.github.com/PortSwigger/BChecks/zip/refs/heads/main",
).strip()
BCHECKS_SYNC_ON_START = _env_flag("BCHECKS_SYNC_ON_START", "false")
STATE_JSONL_MAX_RECORDS = int(os.environ.get("STATE_JSONL_MAX_RECORDS", "2000"))
HYPOTHESIS_STATE_JSONL_MAX_RECORDS = int(os.environ.get("HYPOTHESIS_STATE_JSONL_MAX_RECORDS", str(STATE_JSONL_MAX_RECORDS)))
ANALYSIS_RUN_STATE_JSONL_MAX_RECORDS = int(os.environ.get("ANALYSIS_RUN_STATE_JSONL_MAX_RECORDS", str(STATE_JSONL_MAX_RECORDS)))
PROVIDER_DIAGNOSTICS_JSONL_MAX_RECORDS = int(os.environ.get("PROVIDER_DIAGNOSTICS_JSONL_MAX_RECORDS", str(STATE_JSONL_MAX_RECORDS)))
PHASE_SNAPSHOT_JSONL_MAX_RECORDS = int(os.environ.get("PHASE_SNAPSHOT_JSONL_MAX_RECORDS", str(STATE_JSONL_MAX_RECORDS)))
BURP_SESSION_SNAPSHOT_JSONL_MAX_RECORDS = int(os.environ.get("BURP_SESSION_SNAPSHOT_JSONL_MAX_RECORDS", str(min(STATE_JSONL_MAX_RECORDS, 1000))))
ISSUE_WORKFLOW_STATE_JSONL_MAX_RECORDS = int(os.environ.get("ISSUE_WORKFLOW_STATE_JSONL_MAX_RECORDS", str(min(STATE_JSONL_MAX_RECORDS, 1500))))
HISTORY_JSONL_MAX_RECORDS = int(os.environ.get("HISTORY_JSONL_MAX_RECORDS", "2000"))
AUDIT_LOG_JSONL_MAX_RECORDS = int(os.environ.get("AUDIT_LOG_JSONL_MAX_RECORDS", str(min(HISTORY_JSONL_MAX_RECORDS, 1500))))
REVIEW_DATASET_JSONL_MAX_RECORDS = int(os.environ.get("REVIEW_DATASET_JSONL_MAX_RECORDS", str(min(HISTORY_JSONL_MAX_RECORDS, 1000))))
REPEATER_LEARNING_JSONL_MAX_RECORDS = int(os.environ.get("REPEATER_LEARNING_JSONL_MAX_RECORDS", str(min(HISTORY_JSONL_MAX_RECORDS, 1200))))
BENCHMARK_SNAPSHOT_ENABLED = _env_flag("BENCHMARK_SNAPSHOT_ENABLED", "true")
BENCHMARK_SNAPSHOT_MAX_RECORDS = int(os.environ.get("BENCHMARK_SNAPSHOT_MAX_RECORDS", "120"))
TARGET_MEMORY_PARTITIONING_ENABLED = _env_flag("TARGET_MEMORY_PARTITIONING_ENABLED", "true")
PERSISTENCE_REPLAY_PROTECTION_MODE = os.environ.get("PERSISTENCE_REPLAY_PROTECTION_MODE", "hash-raw").strip().lower()
PERSISTENCE_STORAGE_SEAL_KEY = os.environ.get("PERSISTENCE_STORAGE_SEAL_KEY", "").strip()
OBSERVABILITY_REQUIRE_LOCAL_OR_AUTH = _env_flag("OBSERVABILITY_REQUIRE_LOCAL_OR_AUTH", "true")
OBSERVABILITY_ALLOW_LOCALHOST = _env_flag("OBSERVABILITY_ALLOW_LOCALHOST", "true")
OBSERVABILITY_AUTH_TOKEN = os.environ.get("OBSERVABILITY_AUTH_TOKEN", "").strip()
