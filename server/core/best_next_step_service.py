from __future__ import annotations

from typing import Any


def build_one_best_next_step(
    *,
    title: str,
    source: str,
    why: str,
    manual_step: str,
    expected_signal: str,
    stop_when: str,
    supporting_references: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "title": (title or "").strip(),
        "source": (source or "").strip(),
        "why": (why or "").strip(),
        "manual_step": (manual_step or "").strip(),
        "expected_signal": (expected_signal or "").strip(),
        "stop_when": (stop_when or "").strip(),
        "supporting_references": list(supporting_references or [])[:6],
    }


def build_best_next_step_from_matrix(
    *,
    next_try_matrix: list[dict[str, Any]] | None = None,
    fallback_title: str = "",
    fallback_why: str = "",
    fallback_expected_signal: str = "",
    fallback_stop_when: str = "",
    source: str = "analysis-plan",
    supporting_references: list[str] | None = None,
) -> dict[str, Any]:
    matrix = list(next_try_matrix or [])
    item = matrix[0] if matrix else {}
    return build_one_best_next_step(
        title=str(item.get("what_to_try") or fallback_title or "Capture one bounded next proof."),
        source=source,
        why=str(item.get("how_it_helps") or fallback_why or "This is the strongest bounded next step right now."),
        manual_step=str(item.get("what_to_try") or fallback_title or "Capture one bounded next proof."),
        expected_signal=str(item.get("impact_signal") or fallback_expected_signal or "One cleaner, bounded signal than the current baseline."),
        stop_when=str(item.get("evidence_to_capture") or fallback_stop_when or "One reproducible artifact is captured."),
        supporting_references=supporting_references,
    )
