from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import re
from statistics import mean
from typing import Any

from server.history_store import read_history_records
from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.repeater_learning import read_repeater_learning
from server.state.store import read_issue_workflow_states, read_provider_diagnostics
from server.settings import (
    BENCHMARK_SNAPSHOT_ENABLED,
    BENCHMARK_SNAPSHOT_MAX_RECORDS,
    OLLAMA_CODE_MODEL,
    OLLAMA_DEEP_MODEL,
    OLLAMA_FAST_MODEL,
    OLLAMA_MODEL,
)

BENCHMARK_SNAPSHOT_PATH = MEMORY_DIR / "runtime_benchmark_snapshots.jsonl"
WORKING_SET_FIELDS = (
    "raw_request",
    "raw_response",
    "tool_results_text",
    "response_delta_text",
    "bapp_findings_text",
    "logger_evidence_text",
    "collaborator_evidence_text",
)


def build_runtime_benchmark(*, limit: int = 100) -> dict[str, Any]:
    history = read_history_records()[-max(1, limit):]
    diagnostics = read_provider_diagnostics(limit=max(1, limit))
    workflows = read_issue_workflow_states(limit=max(1, limit))
    learning = read_repeater_learning(limit=max(1, limit))

    model_latency = _latency_by_model(history)
    memory_by_model = _memory_by_model(history)
    fallback_frequency = _fallback_frequency(history, diagnostics)
    average_context_size = _average_context_size(history)
    suggested_step_success = _suggested_step_success_rate(workflows, learning)
    rollout_comparison = _window_rollout_comparison(history)
    snapshot_state = _persist_and_compare_snapshot(
        window_count=len(history),
        model_latency=model_latency,
        memory_by_model=memory_by_model,
        fallback_frequency=fallback_frequency,
        suggested_step_success=suggested_step_success,
        limit=limit,
    )
    model_matrix = _model_matrix(model_latency, memory_by_model)
    diagnostics_summary = _rollout_diagnostics(
        fallback_frequency=fallback_frequency,
        suggested_step_success=suggested_step_success,
        rollout_comparison=rollout_comparison,
        snapshot_comparison=snapshot_state.get("comparison") or {},
        model_matrix=model_matrix,
    )

    return {
        "window_count": len(history),
        "latency_by_model": model_latency,
        "memory_by_model": memory_by_model,
        "fallback_frequency": fallback_frequency,
        "average_context_size": average_context_size,
        "suggested_step_success_rate": suggested_step_success,
        "rollout_comparison": rollout_comparison,
        "benchmark_snapshots": snapshot_state,
        "model_matrix": model_matrix,
        "diagnostics": diagnostics_summary,
        "summary": _summary(
            model_latency=model_latency,
            memory_by_model=memory_by_model,
            fallback_frequency=fallback_frequency,
            average_context_size=average_context_size,
            suggested_step_success=suggested_step_success,
            rollout_comparison=rollout_comparison,
            diagnostics=diagnostics_summary,
        ),
    }


def _latency_by_model(history: list[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, list[float]] = {}
    for record in history:
        model = _model_name_from_record(record)
        seconds = _record_latency_seconds(record)
        if seconds is None:
            continue
        buckets.setdefault(model, []).append(seconds)
    return {
        model: {
            "count": len(values),
            "avg_seconds": round(mean(values), 3),
            "max_seconds": round(max(values), 3),
        }
        for model, values in buckets.items()
    }


def _memory_by_model(history: list[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, list[float]] = {}
    for record in history:
        model = _model_name_from_record(record)
        payload_kb = _record_working_set_kb(record)
        if payload_kb <= 0:
            continue
        buckets.setdefault(model, []).append(payload_kb)
    return {
        model: {
            "count": len(values),
            "avg_working_set_kb": round(mean(values), 2),
            "max_working_set_kb": round(max(values), 2),
        }
        for model, values in buckets.items()
    }


def _fallback_frequency(history: list[dict[str, Any]], diagnostics: list[dict[str, Any]]) -> dict[str, Any]:
    total = max(1, len(history))
    fallback_count = sum(1 for item in history if bool((item.get("result") or {}).get("fallback_used")))
    mcp_failover_count = 0
    for item in diagnostics:
        failover = item.get("provider_failover") or {}
        if failover.get("mcp_fallback_triggered"):
            mcp_failover_count += 1
    return {
        "history_fallback_rate": round(fallback_count / total, 3),
        "history_fallback_count": fallback_count,
        "mcp_failover_count": mcp_failover_count,
    }


def _average_context_size(history: list[dict[str, Any]]) -> dict[str, Any]:
    sizes: list[int] = []
    for record in history:
        analysis_run = record.get("analysis_run") or {}
        context = analysis_run.get("input_context") or {}
        try:
            sizes.append(len(json.dumps(context, ensure_ascii=True)))
        except TypeError:
            continue
    if not sizes:
        return {"avg_chars": 0, "max_chars": 0}
    return {
        "avg_chars": round(mean(sizes), 2),
        "max_chars": max(sizes),
    }


def _suggested_step_success_rate(workflows: list[dict[str, Any]], learning: list[dict[str, Any]]) -> dict[str, Any]:
    workflow_success = 0
    for item in workflows:
        strongest = item.get("strongest_delta") or {}
        if float(strongest.get("score", 0.0) or 0.0) >= 2.5:
            workflow_success += 1
    workflow_rate = round(workflow_success / max(1, len(workflows)), 3) if workflows else 0.0

    learning_success = sum(1 for item in learning if bool(item.get("suggested_step_success")))
    learning_rate = round(learning_success / max(1, len(learning)), 3) if learning else 0.0
    return {
        "workflow_success_rate": workflow_rate,
        "workflow_success_count": workflow_success,
        "learning_success_rate": learning_rate,
        "learning_success_count": learning_success,
    }


def _record_latency_seconds(record: dict[str, Any]) -> float | None:
    created = record.get("started_at") or record.get("created_at")
    completed = record.get("completed_at")
    if not created or not completed:
        return None
    try:
        from datetime import datetime

        start_dt = datetime.fromisoformat(str(created))
        end_dt = datetime.fromisoformat(str(completed))
        return max(0.0, (end_dt - start_dt).total_seconds())
    except ValueError:
        return None


def _record_working_set_kb(record: dict[str, Any]) -> float:
    total_bytes = 0
    for field_name in WORKING_SET_FIELDS:
        value = record.get(field_name)
        if value is None:
            continue
        total_bytes += len(str(value).encode("utf-8", errors="ignore"))

    analysis_run = record.get("analysis_run") or {}
    context = analysis_run.get("input_context") or {}
    try:
        total_bytes += len(json.dumps(context, ensure_ascii=True).encode("utf-8"))
    except TypeError:
        pass
    return round(total_bytes / 1024.0, 3)


def _window_rollout_comparison(history: list[dict[str, Any]]) -> dict[str, Any]:
    if len(history) < 4:
        return {
            "status": "insufficient-data",
            "summary": "Need at least four completed jobs to compute a before/after rollout comparison.",
            "before": {},
            "after": {},
            "deltas": {},
        }

    split_at = max(1, len(history) // 2)
    before = history[:split_at]
    after = history[split_at:]
    before_metrics = _window_metrics(before)
    after_metrics = _window_metrics(after)
    delta_latency = _delta_percent(before_metrics.get("avg_latency_seconds", 0.0), after_metrics.get("avg_latency_seconds", 0.0))
    delta_memory = _delta_percent(before_metrics.get("avg_working_set_kb", 0.0), after_metrics.get("avg_working_set_kb", 0.0))
    status = _rollout_status(delta_latency, delta_memory)
    return {
        "status": status,
        "summary": _rollout_summary(status, delta_latency, delta_memory),
        "before": before_metrics,
        "after": after_metrics,
        "deltas": {
            "latency_percent": delta_latency,
            "working_set_percent": delta_memory,
        },
    }


def _window_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    latencies: list[float] = []
    working_set_kb: list[float] = []
    for item in records:
        latency = _record_latency_seconds(item)
        if latency is not None:
            latencies.append(latency)
        payload = _record_working_set_kb(item)
        if payload > 0:
            working_set_kb.append(payload)
    return {
        "count": len(records),
        "avg_latency_seconds": round(mean(latencies), 3) if latencies else 0.0,
        "max_latency_seconds": round(max(latencies), 3) if latencies else 0.0,
        "avg_working_set_kb": round(mean(working_set_kb), 2) if working_set_kb else 0.0,
        "max_working_set_kb": round(max(working_set_kb), 2) if working_set_kb else 0.0,
    }


def _delta_percent(before: float, after: float) -> float:
    if before <= 0:
        return 0.0
    return round(((after - before) / before) * 100.0, 2)


def _rollout_status(delta_latency: float, delta_memory: float) -> str:
    if delta_latency <= -10.0 and delta_memory <= 10.0:
        return "improved"
    if delta_latency >= 12.0 or delta_memory >= 20.0:
        return "regressed"
    return "mixed"


def _rollout_summary(status: str, delta_latency: float, delta_memory: float) -> str:
    if status == "improved":
        return (
            f"After rollout, mean latency improved by {abs(delta_latency):.2f}% "
            f"with working-set change {delta_memory:.2f}%."
        )
    if status == "regressed":
        return (
            f"After rollout, latency/memory regressed: latency delta {delta_latency:.2f}%, "
            f"working-set delta {delta_memory:.2f}%."
        )
    return (
        f"Rollout results are mixed: latency delta {delta_latency:.2f}% and "
        f"working-set delta {delta_memory:.2f}%."
    )


def _persist_and_compare_snapshot(
    *,
    window_count: int,
    model_latency: dict[str, Any],
    memory_by_model: dict[str, Any],
    fallback_frequency: dict[str, Any],
    suggested_step_success: dict[str, Any],
    limit: int,
) -> dict[str, Any]:
    if not BENCHMARK_SNAPSHOT_ENABLED:
        return {
            "enabled": False,
            "path": str(BENCHMARK_SNAPSHOT_PATH),
            "latest": {},
            "previous": {},
            "comparison": {},
            "summary": "Benchmark snapshots are disabled.",
        }

    snapshot = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "limit": max(1, int(limit or 1)),
        "window_count": int(window_count or 0),
        "avg_latency_seconds": _average_metric(model_latency, "avg_seconds"),
        "avg_working_set_kb": _average_metric(memory_by_model, "avg_working_set_kb"),
        "fallback_rate": float(fallback_frequency.get("history_fallback_rate", 0.0) or 0.0),
        "workflow_success_rate": float(suggested_step_success.get("workflow_success_rate", 0.0) or 0.0),
    }
    previous = _append_snapshot(snapshot)
    comparison = _snapshot_delta(previous, snapshot)
    summary = comparison.get("summary") or "Saved the first benchmark snapshot."
    return {
        "enabled": True,
        "path": str(BENCHMARK_SNAPSHOT_PATH),
        "latest": snapshot,
        "previous": previous or {},
        "comparison": comparison,
        "summary": summary,
    }


def _append_snapshot(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    ensure_storage()
    previous: dict[str, Any] | None = None
    rows: list[dict[str, Any]] = []
    if BENCHMARK_SNAPSHOT_PATH.exists():
        for line in BENCHMARK_SNAPSHOT_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    if rows:
        previous = rows[-1]
    rows.append(snapshot)
    keep = max(10, int(BENCHMARK_SNAPSHOT_MAX_RECORDS or 120))
    rows = rows[-keep:]
    BENCHMARK_SNAPSHOT_PATH.write_text(
        "".join(json.dumps(item, ensure_ascii=True) + "\n" for item in rows),
        encoding="utf-8",
    )
    return previous


def _snapshot_delta(previous: dict[str, Any] | None, latest: dict[str, Any]) -> dict[str, Any]:
    if not previous:
        return {
            "status": "insufficient-data",
            "summary": "No previous benchmark snapshot is available yet.",
            "delta": {},
        }
    latency_delta = _delta_percent(
        float(previous.get("avg_latency_seconds", 0.0) or 0.0),
        float(latest.get("avg_latency_seconds", 0.0) or 0.0),
    )
    memory_delta = _delta_percent(
        float(previous.get("avg_working_set_kb", 0.0) or 0.0),
        float(latest.get("avg_working_set_kb", 0.0) or 0.0),
    )
    status = _rollout_status(latency_delta, memory_delta)
    return {
        "status": status,
        "summary": _rollout_summary(status, latency_delta, memory_delta),
        "delta": {
            "latency_percent": latency_delta,
            "working_set_percent": memory_delta,
        },
    }


def _average_metric(metric_map: dict[str, Any], field: str) -> float:
    values: list[float] = []
    for item in metric_map.values():
        if not isinstance(item, dict):
            continue
        try:
            values.append(float(item.get(field, 0.0) or 0.0))
        except (TypeError, ValueError):
            continue
    return round(mean(values), 3) if values else 0.0


def _model_matrix(model_latency: dict[str, Any], memory_by_model: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for role, model_name, profiles in [
        ("default", OLLAMA_MODEL, ["mcp-grounded-llama32"]),
        ("fast", OLLAMA_FAST_MODEL, ["low-resource-local"]),
        ("deep", OLLAMA_DEEP_MODEL, ["deep-escalation-local-8b"]),
        ("code", OLLAMA_CODE_MODEL, []),
    ]:
        normalized = (model_name or "").strip()
        latency = _metric_for_model(model_latency, normalized, "avg_seconds")
        working_set = _metric_for_model(memory_by_model, normalized, "avg_working_set_kb")
        estimated_ram_gb = _estimated_model_ram_gb(normalized)
        rows.append(
            {
                "role": role,
                "model": normalized,
                "profiles": profiles,
                "estimated_ram_gb": estimated_ram_gb,
                "recent_avg_latency_seconds": latency,
                "recent_avg_working_set_kb": working_set,
                "recommended_for_16gb": estimated_ram_gb <= 8.5,
            }
        )
    return {
        "rows": rows,
        "summary": "Model matrix for fast/deep/code profiles is tuned for single-model sequential execution on a 16GB machine.",
    }


def _metric_for_model(metric_map: dict[str, Any], model_name: str, field: str) -> float:
    for key, value in metric_map.items():
        if str(key).strip() != str(model_name).strip():
            continue
        try:
            return round(float((value or {}).get(field, 0.0) or 0.0), 3)
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _estimated_model_ram_gb(model_name: str) -> float:
    params = _extract_model_params_b(model_name)
    if params <= 0:
        return 6.0
    # 4-bit local inference estimate with runtime overhead on consumer laptops.
    estimate = (params * 0.72) + 0.9
    return round(max(1.5, estimate), 2)


def _extract_model_params_b(model_name: str) -> float:
    match = re.search(r":(\d+(?:\.\d+)?)b$", str(model_name or "").strip().lower())
    if not match:
        return 0.0
    try:
        return float(match.group(1))
    except ValueError:
        return 0.0


def _rollout_diagnostics(
    *,
    fallback_frequency: dict[str, Any],
    suggested_step_success: dict[str, Any],
    rollout_comparison: dict[str, Any],
    snapshot_comparison: dict[str, Any],
    model_matrix: dict[str, Any],
) -> dict[str, Any]:
    recommendations = []
    fallback_rate = float(fallback_frequency.get("history_fallback_rate", 0.0) or 0.0)
    workflow_success = float(suggested_step_success.get("workflow_success_rate", 0.0) or 0.0)
    rollout_status = str(rollout_comparison.get("status") or "")
    snapshot_status = str(snapshot_comparison.get("status") or "")

    if fallback_rate > 0.35:
        recommendations.append("Fallback rate is high; verify MCP reachability and Ollama endpoint health before enabling deeper passes.")
    if workflow_success < 0.4:
        recommendations.append("Suggested-step success is low; keep scanner issue anchoring and reduce broad variant expansion.")
    if rollout_status == "regressed" or snapshot_status == "regressed":
        recommendations.append("Latest rollout benchmark regressed; keep deep model optional and increase deep-routing thresholds.")
    if not recommendations:
        recommendations.append("Rollout diagnostics look stable for production-safe sequential execution.")

    return {
        "rollout_status": rollout_status or "unknown",
        "snapshot_status": snapshot_status or "unknown",
        "fallback_rate": fallback_rate,
        "workflow_success_rate": workflow_success,
        "model_roles": [item.get("role") for item in model_matrix.get("rows", [])],
        "recommendations": recommendations[:6],
    }


def _model_name_from_record(record: dict[str, Any]) -> str:
    result = record.get("result") or {}
    strategy = result.get("model_strategy") or {}
    return (strategy.get("active_model") or result.get("analysis_backend") or "unknown").strip()


def _summary(
    *,
    model_latency: dict[str, Any],
    memory_by_model: dict[str, Any],
    fallback_frequency: dict[str, Any],
    average_context_size: dict[str, Any],
    suggested_step_success: dict[str, Any],
    rollout_comparison: dict[str, Any],
    diagnostics: dict[str, Any],
) -> str:
    if not model_latency:
        return "Benchmark data is still sparse. Run more jobs before using benchmark mode for tuning."
    fastest = min(model_latency.items(), key=lambda item: item[1].get("avg_seconds", 0.0))[0]
    lightest = min(memory_by_model.items(), key=lambda item: item[1].get("avg_working_set_kb", 0.0))[0] if memory_by_model else "unknown"
    rollout_status = rollout_comparison.get("status", "unknown")
    return (
        f"Fastest recent model: {fastest}. "
        f"Lowest measured working-set model: {lightest}. "
        f"Fallback rate: {fallback_frequency.get('history_fallback_rate', 0.0)}. "
        f"Average context size: {average_context_size.get('avg_chars', 0)} chars. "
        f"Suggested-step success rate: {suggested_step_success.get('workflow_success_rate', 0.0)}. "
        f"Rollout status: {rollout_status}. "
        f"Diagnostics: {(diagnostics.get('recommendations') or ['none'])[0]}"
    )
