ACTION_SAFE_NOW = "safe-now"
ACTION_NEEDS_CONFIRMATION = "needs-confirmation"
ACTION_HIGH_SIGNAL = "high-signal"
ACTION_MANUAL_REVIEW = "manual-review-required"
ACTION_OUT_OF_SCOPE_RISK = "out-of-scope-risk"


def label_action(text: str, label: str) -> dict:
    return {
        "label": label,
        "text": (text or "").strip(),
    }


def infer_action_label(text: str, fallback_used: bool = False, high_signal: bool = False) -> str:
    normalized = (text or "").strip().lower()
    if not normalized:
        return ACTION_MANUAL_REVIEW
    if "out of scope" in normalized or "program rule" in normalized:
        return ACTION_OUT_OF_SCOPE_RISK
    if fallback_used:
        return ACTION_NEEDS_CONFIRMATION
    if high_signal or any(token in normalized for token in ("confirm", "baseline", "compare", "capture evidence", "repeater")):
        return ACTION_HIGH_SIGNAL
    if any(token in normalized for token in ("review", "assess", "inspect", "decide", "report")):
        return ACTION_MANUAL_REVIEW
    return ACTION_SAFE_NOW


def label_actions(items: list[str], fallback_used: bool = False, high_signal_count: int = 2) -> list[dict]:
    labeled: list[dict] = []
    for index, item in enumerate(items):
        if not (item or "").strip():
            continue
        label = infer_action_label(item, fallback_used=fallback_used, high_signal=index < high_signal_count)
        labeled.append(label_action(item, label))
    return labeled
