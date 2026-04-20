import copy
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import _threads_queues, _worker
from datetime import datetime, timezone
import weakref

from server.audit_logger import append_audit_event
from server.core.analysis_service import analyze_exchange_bounded
from server.capabilities.burp import normalize_burp_payload_contract
from server.history_store import append_history_record
from server.capabilities.memory import build_history_fingerprint
from server.providers.deterministic_provider import build_deterministic_context
from server.settings import (
    ANALYSIS_LOOP_HARD_STEP_CAP,
    ANALYSIS_LOOP_MAX_STEPS,
    ANALYSIS_LOOP_SCANNER_MAX_STEPS,
    MODEL_SCHEDULER_SEQUENTIAL_ONLY,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DaemonThreadPoolExecutor(ThreadPoolExecutor):
    def _adjust_thread_count(self):
        if self._idle_semaphore.acquire(timeout=0):
            return

        def weakref_cb(_, q=self._work_queue):
            q.put(None)

        num_threads = len(self._threads)
        if num_threads < self._max_workers:
            thread_name = "%s_%d" % (self._thread_name_prefix or self, num_threads)
            worker_thread = threading.Thread(
                name=thread_name,
                target=_worker,
                args=(
                    weakref.ref(self, weakref_cb),
                    self._work_queue,
                    self._initializer,
                    self._initargs,
                ),
            )
            worker_thread.daemon = True
            worker_thread.start()
            self._threads.add(worker_thread)
            _threads_queues[worker_thread] = self._work_queue


class AnalysisJobManager:
    def __init__(self, max_workers: int = 2, max_retained_terminal_jobs: int = 200):
        self._executor = DaemonThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ai-bridge-job")
        self._lock = threading.Lock()
        self._scheduler_lock = threading.Lock()
        self._jobs: dict[str, dict] = {}
        self._max_retained_terminal_jobs = max_retained_terminal_jobs
        self._is_shutdown = False

    def submit(self, payload) -> dict:
        if hasattr(payload, "model_dump"):
            normalized_payload = normalize_burp_payload_contract(payload)
            if hasattr(payload, "model_copy"):
                payload = payload.model_copy(update=normalized_payload)
            else:
                payload = payload.copy(update=normalized_payload)
        rule_context = build_deterministic_context(payload)
        complexity = rule_context["complexity"]
        fingerprint = build_history_fingerprint(payload, rule_context)
        job_id = str(uuid.uuid4())

        job = {
            "job_id": job_id,
            "request_id": getattr(payload, "request_id", "") or "",
            "snapshot_id": getattr(payload, "snapshot_id", "") or "",
            "status": "queued",
            "status_message": (
                f"Analysis queued. Complexity is {complexity['level']} and may take {complexity['eta']}. "
                f"{complexity['recommendation']}"
            ),
            "estimated_duration": complexity["eta"],
            "complexity": complexity["level"],
            "recommendation": complexity["recommendation"],
            "created_at": _utc_now(),
            "started_at": None,
            "completed_at": None,
            "target_url": getattr(payload, "target_url", "") or "",
            "http_method": getattr(payload, "http_method", "") or "",
            "use_burp_mcp_context": bool(getattr(payload, "use_burp_mcp_context", False)),
            "batch_id": getattr(payload, "batch_id", "") or "",
            "batch_index": int(getattr(payload, "batch_index", 0) or 0),
            "batch_total": int(getattr(payload, "batch_total", 0) or 0),
            "selected_profile": getattr(payload, "selected_profile", "") or "",
            "enable_js_endpoint_extraction": bool(getattr(payload, "enable_js_endpoint_extraction", False)),
            "enable_race_signal_checks": bool(getattr(payload, "enable_race_signal_checks", False)),
            "review_scope_include_classes": list(getattr(payload, "review_scope_include_classes", []) or []),
            "review_scope_exclude_classes": list(getattr(payload, "review_scope_exclude_classes", []) or []),
            "browser_verification_allowed": bool(getattr(payload, "browser_verification_allowed", False)),
            "browser_allowed_workflows": list(getattr(payload, "browser_allowed_workflows", []) or []),
            "browser_verification_notes": getattr(payload, "browser_verification_notes", "") or "",
            "privacy_mode_override": getattr(payload, "privacy_mode_override", "") or "",
            "scope_includes_text": getattr(payload, "scope_includes_text", "") or "",
            "scope_excludes_text": getattr(payload, "scope_excludes_text", "") or "",
            "rate_limit_text": getattr(payload, "rate_limit_text", "") or "",
            "max_concurrency_text": getattr(payload, "max_concurrency_text", "") or "",
            "custom_headers_text": getattr(payload, "custom_headers_text", "") or "",
            "program_policy_text": getattr(payload, "program_policy_text", "") or "",
            "program_platform": getattr(payload, "program_platform", "") or "",
            "program_policy_template": getattr(payload, "program_policy_template", "") or "",
            "tool_results_text": getattr(payload, "tool_results_text", "") or "",
            "response_delta_text": getattr(payload, "response_delta_text", "") or "",
            "bapp_findings_text": getattr(payload, "bapp_findings_text", "") or "",
            "logger_evidence_text": getattr(payload, "logger_evidence_text", "") or "",
            "collaborator_evidence_text": getattr(payload, "collaborator_evidence_text", "") or "",
            "evidence_timeline_entries": list(getattr(payload, "evidence_timeline_entries", []) or []),
            "burp_dashboard_issue": getattr(payload, "burp_dashboard_issue", {}) or {},
            "burp_related_scanner_issues": list(getattr(payload, "burp_related_scanner_issues", []) or []),
            "proxy_history_entries": list(getattr(payload, "proxy_history_entries", []) or []),
            "logger_entries": list(getattr(payload, "logger_entries", []) or []),
            "repeater_requests": list(getattr(payload, "repeater_requests", []) or []),
            "project_config_snapshot": getattr(payload, "project_config_snapshot", {}) or {},
            "fingerprint": fingerprint,
            "analysis_loop_step_cap": _default_loop_step_cap(payload),
            "analysis_loop_hard_cap": max(1, int(ANALYSIS_LOOP_HARD_STEP_CAP or 1)),
            "result": None,
            "analysis_run": None,
            "error": None,
        }

        with self._lock:
            if self._is_shutdown:
                raise RuntimeError("The analysis job manager is shutting down.")
            self._jobs[job_id] = job
            self._prune_terminal_jobs_locked()

        payload_copy = copy.deepcopy(payload)
        self._executor.submit(self._run_job, job_id, payload_copy, complexity)
        return copy.deepcopy(job)

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return copy.deepcopy(job) if job else None

    def shutdown(self, cancel_pending: bool = True) -> None:
        with self._lock:
            if self._is_shutdown:
                return
            self._is_shutdown = True
        self._executor.shutdown(wait=False, cancel_futures=cancel_pending)

    def _run_job(self, job_id: str, payload, complexity: dict) -> None:
        self._update(
            job_id,
            status="running",
            started_at=_utc_now(),
            status_message=(
                f"Analysis running. Complexity is {complexity['level']} and may take {complexity['eta']}. "
                f"{complexity['recommendation']}"
            ),
        )

        try:
            step_cap = _job_loop_step_cap(payload)
            if MODEL_SCHEDULER_SEQUENTIAL_ONLY:
                with self._scheduler_lock:
                    analysis_bundle = analyze_exchange_bounded(payload, step_cap=step_cap)
            else:
                analysis_bundle = analyze_exchange_bounded(payload, step_cap=step_cap)
            advisory = analysis_bundle["advisory"]
            analysis_run = analysis_bundle["run"]
            self._update(
                job_id,
                status="completed",
                completed_at=_utc_now(),
                status_message="Analysis completed successfully.",
                result=advisory,
                analysis_run=analysis_run,
            )
            append_audit_event("job_completed", {
                "job_id": job_id,
                "request_id": getattr(payload, "request_id", "") or "",
                "target_url": getattr(payload, "target_url", "") or "",
                "http_method": getattr(payload, "http_method", "") or "",
                "privacy_mode_override": getattr(payload, "privacy_mode_override", "") or "",
                "vuln_count": len(advisory.get("potential_vulnerabilities", [])),
            })
            self._persist(job_id)
        except Exception as exception:
            self._update(
                job_id,
                status="failed",
                completed_at=_utc_now(),
                status_message="Analysis failed.",
                error=str(exception),
            )
            append_audit_event("job_failed", {
                "job_id": job_id,
                "request_id": getattr(payload, "request_id", "") or "",
                "target_url": getattr(payload, "target_url", "") or "",
                "http_method": getattr(payload, "http_method", "") or "",
                "privacy_mode_override": getattr(payload, "privacy_mode_override", "") or "",
                "error": str(exception),
            })
            self._persist(job_id)

    def _update(self, job_id: str, **changes) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.update(changes)
            self._prune_terminal_jobs_locked()

    def _prune_terminal_jobs_locked(self) -> None:
        if self._max_retained_terminal_jobs <= 0:
            return

        terminal_jobs = [
            (job_id, job)
            for job_id, job in self._jobs.items()
            if job.get("status") in {"completed", "failed"}
        ]
        excess = len(terminal_jobs) - self._max_retained_terminal_jobs
        if excess <= 0:
            return

        terminal_jobs.sort(
            key=lambda item: (
                item[1].get("completed_at") or item[1].get("created_at") or "",
                item[0],
            )
        )
        for job_id, _ in terminal_jobs[:excess]:
            self._jobs.pop(job_id, None)

    def _persist(self, job_id: str) -> None:
        snapshot = self.get(job_id)
        if snapshot is None:
            return
        append_history_record(snapshot)


def _default_loop_step_cap(payload) -> int:
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    if "scanner" in source_tool:
        return max(1, int(ANALYSIS_LOOP_SCANNER_MAX_STEPS or 1))
    return max(1, int(ANALYSIS_LOOP_MAX_STEPS or 1))


def _job_loop_step_cap(payload) -> int:
    requested = getattr(payload, "analysis_loop_step_cap", None)
    try:
        requested_cap = int(requested) if requested is not None else 0
    except (TypeError, ValueError):
        requested_cap = 0
    default_cap = _default_loop_step_cap(payload)
    hard_cap = max(1, int(ANALYSIS_LOOP_HARD_STEP_CAP or 1))
    cap = requested_cap if requested_cap > 0 else default_cap
    return max(1, min(cap, hard_cap))
