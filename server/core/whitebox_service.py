from pathlib import Path

from server.settings import WHITEBOX_MAX_FILES, WHITEBOX_MODE_ENABLED, WHITEBOX_ROOT


def whitebox_enrichment(query: str = "") -> dict:
    if not WHITEBOX_MODE_ENABLED:
        return {
            "enabled": False,
            "summary": "White-box mode is disabled.",
            "signals": [],
            "files": [],
        }

    root = Path(WHITEBOX_ROOT).expanduser() if WHITEBOX_ROOT else None
    if root is None or not root.exists():
        return {
            "enabled": True,
            "summary": "White-box mode is enabled but WHITEBOX_ROOT is not configured or does not exist.",
            "signals": [],
            "files": [],
        }

    normalized_query = (query or "").strip().lower()
    keywords = [token for token in normalized_query.replace("/", " ").replace(":", " ").split() if len(token) > 2]
    matches = []
    signals = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".yaml", ".yml", ".json"}:
            continue
        rel = str(path.relative_to(root))
        lowered_rel = rel.lower()
        if keywords and not any(keyword in lowered_rel for keyword in keywords):
            continue
        matches.append(rel)
        if "auth" in lowered_rel:
            signals.append("auth-related source file matched the white-box query.")
        if "session" in lowered_rel:
            signals.append("session-handling source file matched the white-box query.")
        if "upload" in lowered_rel:
            signals.append("file-upload-related source file matched the white-box query.")
        if len(matches) >= max(1, WHITEBOX_MAX_FILES):
            break

    summary = "White-box enrichment found no matching source files."
    if matches:
        summary = f"White-box enrichment matched {len(matches)} source file(s) under {root}."

    deduped_signals = []
    for item in signals:
        if item not in deduped_signals:
            deduped_signals.append(item)
    return {
        "enabled": True,
        "summary": summary,
        "signals": deduped_signals[:8],
        "files": matches,
    }
