import logging
import traceback
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from server.api.handlers import (
    analyze_payload,
    build_burp_payload_contract,
    build_structured_report_for_job,
    normalize_burp_payload,
    prepare_burp_export,
)
from server.burp_mcp_adapter import call_burp_mcp_capability, inspect_burp_mcp_capabilities
from server.burp_asset_feedback import (
    ASSET_FEEDBACK_WEIGHTS,
    append_asset_feedback,
)
from server.analysis_jobs import AnalysisJobManager
from server.audit_logger import append_audit_event, audit_events_jsonl, audit_events_markdown, paginate_audit_events
from server.bcheck_catalog import REPO_DIR, get_bcheck_status, initialize_bchecks, query_bchecks, sync_bchecks_repository
from server.bcheck_learning import append_bcheck_result
from server.capabilities.burp_direct_submit import build_burp_direct_submit_config
from server.capabilities.burp_companion import build_burp_companion_config
from server.capabilities.burp_extension_bundle import build_burp_companion_extension_bundle
from server.capabilities.burp_exporter import build_burp_exporter_config
from server.capabilities.burp import normalize_burp_payload_contract
from server.core.burp_context_service import (
    get_dashboard_issue_context,
    get_logger_deltas,
    get_project_config_snapshot,
    get_recent_proxy_history,
    get_repeater_request,
)
from server.core.burp_action_service import burp_repeater_plan, next_burp_action
from server.core.best_next_step_service import build_one_best_next_step
from server.core.burp_capability_service import recommend_burp_capabilities
from server.core.repeater_dispatch_service import open_repeater_plan
from server.core.repeater_diff_service import score_repeater_diffs
from server.core.repeater_sync_service import sync_repeater_observations
from server.core.burp_panel_service import build_burp_panel_state
from server.core.benchmark_service import build_runtime_benchmark
from server.core.issue_workflow_service import (
    best_next_tab,
    build_workflow_from_observations,
    lookup_issue_workflow,
)
from server.core.burp_snapshot_service import build_burp_session_snapshot
from server.mcp_client import MCPError
from server.core.browser_verification_service import build_browser_verification_plan
from server.core.history_service import (
    build_report_evidence,
    explain_analysis_run,
    query_phase_history,
    query_similar_history,
    update_hypothesis_status,
)
from server.core.hypothesis_service import summarize_hypotheses
from server.core.impact_service import rank_impact_paths
from server.core.impact_upgrade_service import build_program_specific_impact_wording
from server.core.confidence_service import build_confidence_to_claim_map
from server.core.operator_review_service import build_operator_review
from server.core.program_policy_service import get_program_policy_template, list_program_policy_templates
from server.core.runtime_service import (
    get_provider_diagnostics_history,
    get_runtime_health,
    get_runtime_readiness,
    provider_diagnostics_jsonl,
    provider_diagnostics_markdown,
)
from server.core.runtime_model_service import (
    clear_runtime_model_selection,
    get_runtime_model_options,
    list_runtime_profiles,
    select_runtime_model,
)
from server.history_store import (
    batch_summary_markdown,
    history_records_jsonl,
    history_records_markdown,
    get_batch_records,
    get_job_record,
    paginate_history_records,
    job_summary_markdown,
    read_history_records,
    summarize_batch,
)
from server.kali_tools import get_tool_inventory
from server.knowledge_base import KB_DIR, RAG_DIR, rebuild_index, write_note
from server.core.recommendation_service import recommend_bchecks_for_exchange, review_project_readiness
from server.core.report_service import build_structured_report
from server.core.evidence_bundle_service import build_evidence_bundle, render_evidence_bundle_markdown
from server.core.severity_service import assess_submission_severity
from server.core.submission_report_service import build_bug_bounty_submission
from server.core.validation_service import validate_hypothesis
from server.memory_retrieval import (
    FEEDBACK_WEIGHTS,
    append_feedback_record,
    read_feedback_records,
)
from server.local_guidance_db import append_guidance_feedback, query_guidance_packs
from server.submission_regression import (
    build_wording_comparison,
    import_submission_regressions_into_review_dataset,
    query_submission_regressions,
)
from server.issue_family_memory import summarize_issue_family_memory
from server.state.store import get_burp_session_snapshot
from server.settings import (
    BROWSER_VERIFICATION_REQUIRE_EXPLICIT_ALLOW,
    DEFAULT_BOUNTY_PLATFORM,
    OBSERVABILITY_ALLOW_LOCALHOST,
    OBSERVABILITY_AUTH_TOKEN,
    OBSERVABILITY_REQUIRE_LOCAL_OR_AUTH,
)

logger = logging.getLogger("burp_ai_bridge")
job_manager = AnalysisJobManager()


@asynccontextmanager
async def app_lifespan(_: FastAPI):
    try:
        initialize_bchecks()
    except Exception as exception:
        logger.warning("BChecks initialization failed: %s", exception)
    try:
        yield
    finally:
        job_manager.shutdown(cancel_pending=True)


app = FastAPI(title="Burp AI Bridge", lifespan=app_lifespan)


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "") or ""


def _payload_with_request_id(payload: "AssessmentRequest", request: Request) -> "AssessmentRequest":
    if hasattr(payload, "model_copy"):
        return payload.model_copy(update={"request_id": _request_id(request)})
    return payload.copy(update={"request_id": _request_id(request)})


def _handle_internal_error(request: Request, message: str, exc: Exception) -> None:
    request_id = _request_id(request)
    logger.error("%s [request_id=%s]: %s\n%s", message, request_id, exc, traceback.format_exc())
    raise HTTPException(status_code=500, detail={"message": message, "request_id": request_id})


def _apply_analyze_deprecation_headers(response: Response) -> None:
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Tue, 30 Jun 2026 00:00:00 GMT"
    response.headers["Link"] = '</api/analyze/jobs>; rel="successor-version"'
    response.headers["Warning"] = '299 - "/api/analyze is deprecated; use /api/analyze/jobs"'
    response.headers["X-Deprecated-Endpoint"] = "/api/analyze"
    response.headers["X-Preferred-Analysis-Endpoint"] = "/api/analyze/jobs"


def _is_observability_path(path: str) -> bool:
    return path.startswith("/api/history") or path.startswith("/api/runtime") or path.startswith("/api/audit")


def _request_auth_token(request: Request) -> str:
    bearer = (request.headers.get("Authorization") or "").strip()
    if bearer.lower().startswith("bearer "):
        return bearer[7:].strip()
    return (
        (request.headers.get("X-Bridge-Admin-Token") or "").strip()
        or (request.headers.get("X-API-Key") or "").strip()
    )


def _is_local_request_host(request: Request) -> bool:
    forwarded_for = (request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
    host = forwarded_for or ((request.client.host if request.client else "") or "")
    normalized = host.lower()
    return normalized in {"127.0.0.1", "::1", "localhost", "testclient"} or normalized.startswith("127.")


def _observability_access_allowed(request: Request) -> bool:
    if not OBSERVABILITY_REQUIRE_LOCAL_OR_AUTH:
        return True
    if OBSERVABILITY_ALLOW_LOCALHOST and _is_local_request_host(request):
        return True
    configured_token = (OBSERVABILITY_AUTH_TOKEN or "").strip()
    request_token = _request_auth_token(request)
    return bool(configured_token) and request_token == configured_token


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request_id = (request.headers.get("X-Request-ID") or "").strip() or str(uuid.uuid4())
    request.state.request_id = request_id
    if _is_observability_path(request.url.path) and not _observability_access_allowed(request):
        return JSONResponse(
            status_code=403,
            content={
                "detail": {
                    "message": "Observability routes require localhost access or a valid admin token.",
                    "request_id": request_id,
                }
            },
            headers={"X-Request-ID": request_id},
        )
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

class AssessmentRequest(BaseModel):
    request_id: str = ""
    snapshot_id: str = ""
    raw_request: str
    raw_response: Optional[str] = ""
    target_url: Optional[str] = ""
    http_method: Optional[str] = ""
    source_tool: Optional[str] = ""
    use_burp_mcp_context: bool = False
    annotations: List[str] = Field(default_factory=list)
    batch_id: Optional[str] = ""
    batch_index: Optional[int] = 0
    batch_total: Optional[int] = 0
    operator_answers: Dict[str, str] = Field(default_factory=dict)
    tool_help_text: Optional[str] = ""
    scope_includes_text: Optional[str] = ""
    scope_excludes_text: Optional[str] = ""
    rate_limit_text: Optional[str] = ""
    max_concurrency_text: Optional[str] = ""
    custom_headers_text: Optional[str] = ""
    program_policy_text: Optional[str] = ""
    program_platform: Optional[str] = ""
    program_policy_template: Optional[str] = ""
    tool_results_text: Optional[str] = ""
    burp_config_export_text: Optional[str] = ""
    burp_screenshot_audit_text: Optional[str] = ""
    loaded_burp_tools_text: Optional[str] = ""
    saved_program_policy_text: Optional[str] = ""
    program_screenshot_audit_text: Optional[str] = ""
    response_delta_text: Optional[str] = ""
    evidence_timeline_entries: List[str] = Field(default_factory=list)
    bapp_findings_text: Optional[str] = ""
    logger_evidence_text: Optional[str] = ""
    collaborator_evidence_text: Optional[str] = ""
    privacy_mode_override: Optional[str] = ""
    selected_profile: Optional[str] = ""
    enable_js_endpoint_extraction: bool = False
    enable_race_signal_checks: bool = False
    review_scope_include_classes: List[str] = Field(default_factory=list)
    review_scope_exclude_classes: List[str] = Field(default_factory=list)
    browser_verification_allowed: bool = False
    browser_allowed_workflows: List[str] = Field(default_factory=list)
    browser_verification_notes: Optional[str] = ""
    baseline_response_text: Optional[str] = ""
    issue_workflow_notes: List[str] = Field(default_factory=list)
    investigation_notebook_text: Optional[str] = ""
    repeater_variant_observations: List[Dict[str, Any]] = Field(default_factory=list)
    burp_dashboard_issue: Dict[str, Any] = Field(default_factory=dict)
    burp_related_scanner_issues: List[Dict[str, Any]] = Field(default_factory=list)
    proxy_history_entries: List[Dict[str, Any]] = Field(default_factory=list)
    logger_entries: List[Dict[str, Any]] = Field(default_factory=list)
    repeater_requests: List[Dict[str, Any]] = Field(default_factory=list)
    project_config_snapshot: Dict[str, Any] = Field(default_factory=dict)


class BurpContextRequest(AssessmentRequest):
    raw_request: Optional[str] = ""

class AdvisoryResponse(BaseModel):
    request_id: str = ""
    analysis: str
    analysis_backend: str = ""
    model_execution_summary: str = ""
    model_execution_trace: List[str] = Field(default_factory=list)
    provider_failover: "ProviderFailoverResponse" = Field(default_factory=lambda: ProviderFailoverResponse())
    fallback_used: bool = False
    primary_next_action: str = ""
    request_plan: List[str] = Field(default_factory=list)
    tool_availability_summary: str = ""
    potential_vulnerabilities: List[str]
    nuclei_tags: str
    seclists_path: str
    questions_for_user: List[str]
    source_links: List[str] = []
    manual_tooling: List[str] = Field(default_factory=list)
    manual_commands: List[str] = Field(default_factory=list)
    payload_recommendations: List[str] = Field(default_factory=list)
    local_resource_hints: List[str] = Field(default_factory=list)
    bcheck_recommendations: List[str] = Field(default_factory=list)
    impact_paths: List[str] = Field(default_factory=list)
    burp_settings_recommendations: List[str] = Field(default_factory=list)
    project_readiness_summary: str = ""
    project_readiness_checks: List[str] = Field(default_factory=list)
    burp_action_checklist: List[str] = Field(default_factory=list)
    burp_screenshot_review_status: str = ""
    suggestion_queue: List[str] = Field(default_factory=list)
    confidence_by_class: List[str] = Field(default_factory=list)
    history_correlation: List[str] = Field(default_factory=list)
    confirmation_playbooks: List[str] = Field(default_factory=list)
    investigation_phase_state: "InvestigationPhaseStateResponse" = Field(default_factory=lambda: InvestigationPhaseStateResponse())
    contradiction_assessment: "ContradictionAssessmentResponse" = Field(default_factory=lambda: ContradictionAssessmentResponse())
    evidence_sufficiency: "EvidenceSufficiencyResponse" = Field(default_factory=lambda: EvidenceSufficiencyResponse())
    branch_guard: "BranchGuardResponse" = Field(default_factory=lambda: BranchGuardResponse())
    vulnerability_state_machine: "VulnerabilityStateMachineResponse" = Field(default_factory=lambda: VulnerabilityStateMachineResponse())
    counter_hypothesis: "CounterHypothesisResponse" = Field(default_factory=lambda: CounterHypothesisResponse())
    confidence_calibration: "ConfidenceCalibrationResponse" = Field(default_factory=lambda: ConfidenceCalibrationResponse())
    cross_issue_cluster: "CrossIssueClusterResponse" = Field(default_factory=lambda: CrossIssueClusterResponse())
    response_diff_semantics: "ResponseDiffSemanticsResponse" = Field(default_factory=lambda: ResponseDiffSemanticsResponse())
    impact_path_ranking: "ImpactPathRankingResponse" = Field(default_factory=lambda: ImpactPathRankingResponse())
    report_bundle: "ReportBundleResponse" = Field(default_factory=lambda: ReportBundleResponse())
    model_strategy: "ModelStrategyResponse" = Field(default_factory=lambda: ModelStrategyResponse())
    next_try_matrix: List["NextTryItemResponse"] = Field(default_factory=list)
    reporting_impact_notes: List[str] = Field(default_factory=list)
    escalation_profile: str = ""
    baseline_confirmation: str = ""
    safe_vapt_escalation_steps: List[str] = Field(default_factory=list)
    business_impact_expansion_paths: List[str] = Field(default_factory=list)
    required_evidence_for_upgrade: List[str] = Field(default_factory=list)
    stop_conditions: List[str] = Field(default_factory=list)
    likely_severity_promotions: List[str] = Field(default_factory=list)
    escalation_ladder: List[str] = Field(default_factory=list)
    internet_reference_candidates: List[str] = Field(default_factory=list)
    internet_reference_policy: str = ""
    policy_gate: Dict[str, Any] = Field(default_factory=dict)


class InvestigationPhaseStateResponse(BaseModel):
    phase: str = ""
    desired_phase: str = ""
    max_supported_phase: str = ""
    confidence: float = 0.0
    rationale: str = ""
    signals: List[str] = Field(default_factory=list)
    blockers: List[str] = Field(default_factory=list)
    next_gate: str = ""


class ContradictionItemResponse(BaseModel):
    code: str = ""
    severity: str = ""
    summary: str = ""
    evidence: List[str] = Field(default_factory=list)
    recommended_adjustment: str = ""


class ContradictionAssessmentResponse(BaseModel):
    status: str = ""
    raw_status: str = ""
    effective_status: str = ""
    override_applied: bool = False
    override_reason: str = ""
    highest_severity: str = ""
    count: int = 0
    summary: str = ""
    items: List[ContradictionItemResponse] = Field(default_factory=list)


class EvidenceSufficiencyResponse(BaseModel):
    status: str = ""
    raw_status: str = ""
    effective_status: str = ""
    ready_for_phase: str = ""
    raw_ready_for_phase: str = ""
    effective_ready_for_phase: str = ""
    override_applied: bool = False
    override_reason: str = ""
    score: float = 0.0
    evidence_score: float = 0.0
    confirmed_signals: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    missing_artifacts: List[str] = Field(default_factory=list)
    next_best_gate: str = ""
    rationale: str = ""


class BranchGuardResponse(BaseModel):
    status: str = ""
    raw_status: str = ""
    effective_status: str = ""
    override_applied: bool = False
    override_reason: str = ""
    active_branch: str = ""
    deprioritized_branches: List[str] = Field(default_factory=list)
    blocking_reason: str = ""
    effective_blocking_reason: str = ""
    next_best_hypothesis: str = ""
    next_best_step: str = ""
    resume_condition: str = ""
    confidence: float = 0.0
    summary: str = ""
    effective_summary: str = ""


class VulnerabilityStateMachineResponse(BaseModel):
    vuln_class: str = ""
    family: str = ""
    status: str = ""
    raw_status: str = ""
    effective_status: str = ""
    override_applied: bool = False
    override_reason: str = ""
    current_state: str = ""
    next_state: str = ""
    raw_next_state: str = ""
    effective_next_state: str = ""
    goal: str = ""
    preferred_evidence: List[str] = Field(default_factory=list)
    allowed_moves: List[str] = Field(default_factory=list)
    blocked_moves: List[str] = Field(default_factory=list)
    next_if_stalled: str = ""
    alternative_class: str = ""
    alternative_explanation: str = ""
    transition_reason: str = ""
    effective_transition_reason: str = ""


class CounterHypothesisResponse(BaseModel):
    lead_hypothesis: str = ""
    alternative_class: str = ""
    alternative_explanation: str = ""
    status: str = ""
    rejection_confidence: float = 0.0
    rejection_evidence: List[str] = Field(default_factory=list)
    missing_rejection_evidence: List[str] = Field(default_factory=list)
    summary: str = ""


class ConfidenceCalibrationResponse(BaseModel):
    status: str = ""
    base_confidence: float = 0.0
    calibrated_confidence: float = 0.0
    adjustment: float = 0.0
    positive_history_count: int = 0
    review_history_count: int = 0
    fallback_history_count: int = 0
    negative_history_count: int = 0
    preferred_mutation_families: List[str] = Field(default_factory=list)
    deprioritized_mutation_families: List[str] = Field(default_factory=list)
    family_success_rates: Dict[str, float] = Field(default_factory=dict)
    step_ordering_bias: str = ""
    summary: str = ""


class CrossIssueClusterResponse(BaseModel):
    status: str = ""
    cluster_id: str = ""
    host: str = ""
    shared_path_family: str = ""
    shared_parameter_family: str = ""
    issue_count: int = 0
    issue_names: List[str] = Field(default_factory=list)
    merged_vuln_classes: List[str] = Field(default_factory=list)
    supporting_issue_names: List[str] = Field(default_factory=list)
    joined_impact_hints: List[str] = Field(default_factory=list)
    strategy: str = ""
    summary: str = ""


class ResponseDiffSemanticsResponse(BaseModel):
    primary_semantic: str = ""
    semantics: List[str] = Field(default_factory=list)
    status_transitions: List[str] = Field(default_factory=list)
    evidence_markers: List[str] = Field(default_factory=list)
    recommended_comparison_focus: str = ""
    summary: str = ""


class ImpactPathRankingEntryResponse(BaseModel):
    path: str = ""
    score: float = 0.0
    gated: bool = False
    raw_gated: bool = False
    effective_gated: bool = False
    override_applied: bool = False
    override_reason: str = ""
    reasons: List[str] = Field(default_factory=list)


class ImpactPathRankingResponse(BaseModel):
    status: str = ""
    platform: str = ""
    target_type: str = ""
    top_path: str = ""
    ranked_paths: List[ImpactPathRankingEntryResponse] = Field(default_factory=list)
    ranked_path_texts: List[str] = Field(default_factory=list)
    gated_paths: List[str] = Field(default_factory=list)
    submission_value_score: float = 0.0
    summary: str = ""


class ReportBundleResponse(BaseModel):
    status: str = ""
    title: str = ""
    summary: str = ""
    phase: str = ""
    reportability: str = ""
    top_path: str = ""
    impact_statement: str = ""
    platform_focus: str = ""
    platform_wording: str = ""
    submission_value_score: float = 0.0
    confidence: float = 0.0
    proof_bundle: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    burp_workflow: List[str] = Field(default_factory=list)
    related_case_support: List[str] = Field(default_factory=list)
    claim_boundaries: List[str] = Field(default_factory=list)


class HypothesisResponse(BaseModel):
    id: str
    vuln_class: str
    summary: str
    confidence: float
    status: str = "suspected"
    status_notes: str = ""
    status_updated_at: str = ""
    evidence_for: List[str] = Field(default_factory=list)
    evidence_against: List[str] = Field(default_factory=list)
    impact_paths: List[str] = Field(default_factory=list)
    next_checks: List[str] = Field(default_factory=list)


class EvidenceItemResponse(BaseModel):
    source: str
    summary: str
    evidence_type: str = ""
    confidence: float = 0.5
    request_ref: str = ""
    response_ref: str = ""
    delta: str = ""
    notes: str = ""
    timestamp: str = ""


class AnalysisRunResponse(BaseModel):
    request_id: str = ""
    input_context: Dict[str, object] = Field(default_factory=dict)
    phase_results: Dict[str, dict] = Field(default_factory=dict)
    phases: Dict[str, dict] = Field(default_factory=dict)
    hypotheses: List[HypothesisResponse] = Field(default_factory=list)
    evidence: List[EvidenceItemResponse] = Field(default_factory=list)
    provider_trace: List[str] = Field(default_factory=list)
    final_recommendation: str = ""
    fallback_reason: str = ""


class SimilarHistoryMatchResponse(BaseModel):
    job_id: str = ""
    target_url: str = ""
    created_at: str = ""
    similarity: float = 0.0
    shared_classes: List[str] = Field(default_factory=list)
    potential_vulnerabilities: List[str] = Field(default_factory=list)
    hypotheses: List[HypothesisResponse] = Field(default_factory=list)
    evidence_count: int = 0
    feedback_labels: List[str] = Field(default_factory=list)
    analysis_backend: str = ""


class SimilarHistoryResponse(BaseModel):
    fingerprint: Dict[str, object] = Field(default_factory=dict)
    correlation: List[str] = Field(default_factory=list)
    matches: List[SimilarHistoryMatchResponse] = Field(default_factory=list)


class ReportEvidenceHypothesisResponse(BaseModel):
    vuln_class: str = ""
    summary: str = ""
    confidence: float = 0.0
    status: str = ""
    next_checks: List[str] = Field(default_factory=list)


class ReportEvidenceArtifactResponse(BaseModel):
    source: str = ""
    evidence_type: str = ""
    summary: str = ""
    delta: str = ""
    notes: str = ""
    timestamp: str = ""
    confidence: float = 0.0


class ReportEvidenceResponse(BaseModel):
    job_id: str
    request_id: str = ""
    snapshot_id: str = ""
    target_url: str = ""
    http_method: str = ""
    primary_next_action: str = ""
    report_summary: str = ""
    hypothesis_summaries: List[ReportEvidenceHypothesisResponse] = Field(default_factory=list)
    evidence_artifacts: List[ReportEvidenceArtifactResponse] = Field(default_factory=list)
    reporting_checklist: List[str] = Field(default_factory=list)
    confirmation_playbooks: List[str] = Field(default_factory=list)
    source_links: List[str] = Field(default_factory=list)
    analysis_backend: str = ""
    fallback_used: bool = False
    burp_session_snapshot: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeNoteRequest(BaseModel):
    title: str
    content: str
    source: Optional[str] = ""
    tags: Optional[List[str]] = []


class KnowledgeStatusResponse(BaseModel):
    kb_dir: str
    rag_dir: str
    documents: int
    index_present: bool


class GuidanceDbHitResponse(BaseModel):
    id: str = ""
    name: str = ""
    style: str = ""
    origin: str = ""
    summary: str = ""
    matched_classes: List[str] = Field(default_factory=list)
    guidance: Dict[str, List[str]] = Field(default_factory=dict)
    reference_links: List[str] = Field(default_factory=list)
    source_file: str = ""
    feedback_score: int = 0
    decay_score: int = 0
    influence_reason: str = ""


class GuidanceDbResponse(BaseModel):
    hits: List[GuidanceDbHitResponse] = Field(default_factory=list)
    context: str = ""
    reference_links: List[str] = Field(default_factory=list)
    merge_policy: List[str] = Field(default_factory=list)


class ModelStrategyResponse(BaseModel):
    profile: str = ""
    active_model: str = ""
    recommended_model: str = ""
    fast_model: str = ""
    deep_model: str = ""
    code_model: str = ""
    best_for: str = ""
    notes: List[str] = Field(default_factory=list)


class NextTryItemResponse(BaseModel):
    phase: str = ""
    what_to_try: str = ""
    how_it_helps: str = ""
    evidence_to_capture: str = ""
    impact_signal: str = ""


class ProfileResponse(BaseModel):
    name: str
    description: str
    default_review_scope: List[str]
    kb_top_k: int
    memory_top_k: int
    prefer_small_context: bool
    recommended_model: str = ""
    best_for: str = ""
    resolved_model: str = ""
    model_available: bool = False
    switch_value: str = ""
    availability_reason: str = ""


class RuntimeInstalledModelResponse(BaseModel):
    name: str = ""
    size: str = ""
    source: str = ""
    family: str = ""
    current: bool = False
    role_hints: List[str] = Field(default_factory=list)
    profile_matches: List[str] = Field(default_factory=list)


class RuntimeModelSwitchTargetsResponse(BaseModel):
    active: str = ""
    fast: str = ""
    deep: str = ""
    code: str = ""


class RuntimeModelOverrideResponse(BaseModel):
    active: bool = False
    model: str = ""
    source: str = ""
    actor: str = ""
    updated_at: str = ""


class RuntimeModelOptionsResponse(BaseModel):
    configured_url: str = ""
    current_model: str = ""
    installed_models: List[RuntimeInstalledModelResponse] = Field(default_factory=list)
    detected_model_names: List[str] = Field(default_factory=list)
    switch_targets: RuntimeModelSwitchTargetsResponse = Field(default_factory=RuntimeModelSwitchTargetsResponse)
    manual_override: RuntimeModelOverrideResponse = Field(default_factory=RuntimeModelOverrideResponse)
    notes: List[str] = Field(default_factory=list)


class RuntimeModelSelectionRequest(BaseModel):
    model_name: str
    source: str = "api"
    actor: str = ""


class BCheckCatalogEntryResponse(BaseModel):
    name: str
    description: str
    author: str
    language: str
    tags: List[str] = Field(default_factory=list)
    relative_path: str
    collection: str
    source_url: str
    scan_mode: str
    execution_context: str
    requires_collaborator: bool
    methods: List[str] = Field(default_factory=list)
    vuln_classes: List[str] = Field(default_factory=list)
    usage_hint: str


class BCheckStatusResponse(BaseModel):
    available: bool
    repo_dir: str
    source_url: str
    total_checks: int
    top_level_groups: List[str] = Field(default_factory=list)
    mapped_vuln_classes: List[str] = Field(default_factory=list)
    last_updated: str = ""


class BCheckSyncResponse(BCheckStatusResponse):
    synced: bool
    detail: str


class BCheckContentResponse(BaseModel):
    relative_path: str
    name: str
    content: str


class KaliToolResponse(BaseModel):
    name: str
    binary: str
    repo_url: str
    summary: str
    install_hint: str
    installed: bool
    command_path: str = ""
    version: str = ""
    help_preview: str = ""


class KaliToolInventoryResponse(BaseModel):
    available: bool
    distro: str
    distro_name: str = ""
    detected_at: str
    installed_count: int
    missing_count: int
    tool_help_text: str = ""
    error: str = ""
    tools: List[KaliToolResponse] = Field(default_factory=list)


class LabeledActionResponse(BaseModel):
    label: str
    text: str


class ProviderOutcomeResponse(BaseModel):
    provider: str = ""
    status: str = ""
    detail: str = ""
    adopted_fields: List[str] = Field(default_factory=list)
    missing_fields: List[str] = Field(default_factory=list)


class ProviderFailoverResponse(BaseModel):
    provider_order: List[str] = Field(default_factory=list)
    outcomes: List[ProviderOutcomeResponse] = Field(default_factory=list)
    successful_providers: List[str] = Field(default_factory=list)
    final_backend: str = ""
    final_status: str = ""
    fallback_used: bool = False
    deterministic_backfill_used: bool = False
    missing_fields: List[str] = Field(default_factory=list)
    mcp_fallback_triggered: bool = False


class OneBestNextStepResponse(BaseModel):
    title: str = ""
    source: str = ""
    why: str = ""
    manual_step: str = ""
    expected_signal: str = ""
    stop_when: str = ""
    supporting_references: List[str] = Field(default_factory=list)


class OfficialBCheckSelectionResponse(BaseModel):
    name: str = ""
    description: str = ""
    author: str = ""
    language: str = ""
    tags: List[str] = Field(default_factory=list)
    relative_path: str = ""
    collection: str = ""
    source_url: str = ""
    scan_mode: str = ""
    execution_context: str = ""
    requires_collaborator: bool = False
    methods: List[str] = Field(default_factory=list)
    vuln_classes: List[str] = Field(default_factory=list)
    usage_hint: str = ""
    why: str = ""
    score: float = 0.0
    learning_adjustment: float = 0.0
    suppressed_for_issue_family: bool = False
    preferred_for_issue_family: bool = False
    selection_references: List[str] = Field(default_factory=list)


class BCheckRecommendationResponse(BaseModel):
    target_url: str = ""
    recommended_bchecks: List[str] = Field(default_factory=list)
    matched_playbooks: List[str] = Field(default_factory=list)
    review_scope_include_classes: List[str] = Field(default_factory=list)
    official_bcheck_candidates: List[OfficialBCheckSelectionResponse] = Field(default_factory=list)
    selected_official_bcheck: OfficialBCheckSelectionResponse = Field(default_factory=OfficialBCheckSelectionResponse)
    issue_family_memory: Dict[str, Any] = Field(default_factory=dict)
    one_best_next_step: OneBestNextStepResponse = Field(default_factory=OneBestNextStepResponse)
    curated_reference_links: List[str] = Field(default_factory=list)


class ProjectReadinessResponse(BaseModel):
    target_url: str = ""
    project_readiness_summary: str = ""
    project_readiness_checks: List[str] = Field(default_factory=list)
    labeled_project_readiness_checks: List[LabeledActionResponse] = Field(default_factory=list)
    burp_action_checklist: List[str] = Field(default_factory=list)
    bcheck_recommendations: List[str] = Field(default_factory=list)


class ProgramPolicyTemplateResponse(BaseModel):
    name: str
    platform: str
    summary: str
    scope_prompts: List[str] = Field(default_factory=list)
    rate_limit_guidance: List[str] = Field(default_factory=list)
    safe_testing_notes: List[str] = Field(default_factory=list)
    browser_verification_rules: List[str] = Field(default_factory=list)
    out_of_scope_risks: List[str] = Field(default_factory=list)
    report_expectations: List[str] = Field(default_factory=list)
    effective_policy_text: str = ""
    explicit_policy_supplied: bool = False


class HypothesisSummaryItemResponse(BaseModel):
    id: str = ""
    vuln_class: str = "general"
    summary: str = ""
    confidence: float = 0.0
    status: str = "suspected"
    status_notes: str = ""
    impact_paths: List[str] = Field(default_factory=list)
    next_checks: List[str] = Field(default_factory=list)
    evidence_signal_count: int = 0
    contradiction_count: int = 0


class HypothesisSummaryResponse(BaseModel):
    target_url: str = ""
    primary_hypothesis: Optional[HypothesisSummaryItemResponse] = None
    hypotheses: List[HypothesisSummaryItemResponse] = Field(default_factory=list)
    hypothesis_count: int = 0
    evidence_count: int = 0
    evidence_sources: List[str] = Field(default_factory=list)
    analysis_backend: str = ""
    fallback_used: bool = False


class HypothesisValidationResponse(BaseModel):
    target_url: str = ""
    hypothesis: Optional[HypothesisResponse] = None
    validation_status: str = ""
    confidence: float = 0.0
    evidence_sources: List[str] = Field(default_factory=list)
    confirming_sources: List[str] = Field(default_factory=list)
    evidence_score: float = 0.0
    evidence_count: int = 0
    missing_evidence: List[str] = Field(default_factory=list)
    confirmation_requirements: List[str] = Field(default_factory=list)
    safest_next_proof: str = ""
    recommended_actions: List[LabeledActionResponse] = Field(default_factory=list)
    analysis_backend: str = ""
    fallback_used: bool = False


class BrowserVerificationResponse(BaseModel):
    target_url: str = ""
    program_platform: str = ""
    eligible: bool = False
    allowed: bool = False
    reason: str = ""
    verification_goal: str = ""
    validation_status: str = ""
    reportability: str = ""
    requires_manual_session: bool = False
    allowed_workflows: List[str] = Field(default_factory=list)
    checkpoints: List[str] = Field(default_factory=list)
    evidence_to_capture: List[str] = Field(default_factory=list)
    policy_notes: List[str] = Field(default_factory=list)
    stop_conditions: List[str] = Field(default_factory=list)
    out_of_scope_risks: List[str] = Field(default_factory=list)
    suggested_steps: List[str] = Field(default_factory=list)
    labeled_steps: List[LabeledActionResponse] = Field(default_factory=list)


class BurpEntryResponse(BaseModel):
    source: str = ""
    summary: str = ""
    method: str = ""
    url: str = ""
    status_code: str = ""
    notes: str = ""
    request_ref: str = ""
    response_ref: str = ""
    timestamp: str = ""


class BurpIssueContextResponse(BaseModel):
    found: bool = False
    issue_id: str = ""
    issue_name: str = ""
    severity: str = ""
    confidence: str = ""
    host: str = ""
    path: str = ""
    target_url: str = ""
    affected_urls: List[str] = Field(default_factory=list)
    background: str = ""
    detail: str = ""
    remediation: str = ""
    evidence_items: List[str] = Field(default_factory=list)
    request_refs: List[str] = Field(default_factory=list)
    response_refs: List[str] = Field(default_factory=list)
    vuln_hint: str = ""


class BurpEntriesResponse(BaseModel):
    target_url: str = ""
    count: int = 0
    entries: List[BurpEntryResponse] = Field(default_factory=list)


class RepeaterRequestResponse(BurpEntriesResponse):
    primary_request: BurpEntryResponse = Field(default_factory=BurpEntryResponse)


class BurpProjectConfigResponse(BaseModel):
    selected_profile: str = ""
    enabled_tools: List[str] = Field(default_factory=list)
    scope_includes: List[str] = Field(default_factory=list)
    scope_excludes: List[str] = Field(default_factory=list)
    rate_limit_notes: str = ""
    concurrency_notes: str = ""
    custom_headers_notes: str = ""
    program_policy: str = ""
    config_warnings: List[str] = Field(default_factory=list)


class BurpContextSummaryResponse(BaseModel):
    dashboard_issue: BurpIssueContextResponse = Field(default_factory=BurpIssueContextResponse)
    related_scanner_issue_count: int = 0
    related_scanner_issue_names: List[str] = Field(default_factory=list)
    proxy_history_count: int = 0
    logger_entry_count: int = 0
    repeater_request_count: int = 0
    enabled_tool_count: int = 0
    config_warning_count: int = 0


class BurpCapabilityRecommendationResponse(BaseModel):
    tool: str = ""
    capability: str = ""
    available: bool = False
    why: str = ""
    manual_step: str = ""
    expected_signal: str = ""
    stop_when: str = ""
    mcp_tool_name: str = ""
    mode: str = ""
    recommended_asset_type: str = ""
    recommended_asset_id: str = ""
    recommended_asset_name: str = ""
    recommended_asset_path: str = ""


class ImpactUpgradePlannerResponse(BaseModel):
    vuln_class: str = ""
    current_proof_level: str = ""
    next_strongest_allowed_step: str = ""
    missing_artifact_for_upgrade: str = ""
    likely_severity_if_confirmed: str = ""
    report_ready_impact_sentence: str = ""
    impact_ladder: List[str] = Field(default_factory=list)


class FindingToImpactTemplateResponse(BaseModel):
    vuln_class: str = ""
    proof_level: str = ""
    impact_ladder: List[str] = Field(default_factory=list)
    report_ready_impact_sentence: str = ""


class ReportabilityGateResponse(BaseModel):
    already_proven: List[str] = Field(default_factory=list)
    still_inferred: List[str] = Field(default_factory=list)
    unsafe_to_claim_yet: List[str] = Field(default_factory=list)


class SubmissionValueScoreResponse(BaseModel):
    score: float = 0.0
    platform: str = ""
    components: Dict[str, float] = Field(default_factory=dict)
    platform_adjustment: float = 0.0
    platform_notes: List[str] = Field(default_factory=list)
    summary: str = ""


class ProgramSpecificImpactWordingResponse(BaseModel):
    platform: str = ""
    focus: str = ""
    wording: str = ""


class ImpactAssessmentResponse(BaseModel):
    target_url: str = ""
    recommended_path: str = ""
    ranked_impact_paths: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    confirmation_requirements: List[str] = Field(default_factory=list)
    safest_next_proof: str = ""
    effective_safest_next_proof: str = ""
    safe_vapt_escalation_steps: List[str] = Field(default_factory=list)
    labeled_safe_vapt_escalation_steps: List[LabeledActionResponse] = Field(default_factory=list)
    escalation_profile: str = ""
    baseline_confirmation: str = ""
    business_impact_expansion_paths: List[str] = Field(default_factory=list)
    effective_business_impact_expansion_paths: List[str] = Field(default_factory=list)
    required_evidence_for_upgrade: List[str] = Field(default_factory=list)
    stop_conditions: List[str] = Field(default_factory=list)
    likely_severity_promotions: List[str] = Field(default_factory=list)
    business_impact_class: str = ""
    confirmation_state: str = ""
    reportable: bool = False
    reportability: str = ""
    hypothesis_count: int = 0
    evidence_score: float = 0.0
    evidence_count: int = 0
    dashboard_issue: BurpIssueContextResponse = Field(default_factory=BurpIssueContextResponse)
    burp_context_summary: BurpContextSummaryResponse = Field(default_factory=BurpContextSummaryResponse)
    action_items: List[LabeledActionResponse] = Field(default_factory=list)
    analysis_backend: str = ""
    fallback_used: bool = False
    escalation_ladder: List[str] = Field(default_factory=list)
    reference_links: List[str] = Field(default_factory=list)
    internet_reference_candidates: List[str] = Field(default_factory=list)
    internet_reference_policy: str = ""
    policy_gate: Dict[str, Any] = Field(default_factory=dict)
    next_try_matrix: List[NextTryItemResponse] = Field(default_factory=list)
    reporting_impact_notes: List[str] = Field(default_factory=list)
    impact_upgrade_planner: ImpactUpgradePlannerResponse = Field(default_factory=ImpactUpgradePlannerResponse)
    finding_to_impact_template: FindingToImpactTemplateResponse = Field(default_factory=FindingToImpactTemplateResponse)
    reportability_gate: ReportabilityGateResponse = Field(default_factory=ReportabilityGateResponse)
    program_specific_impact_wording: ProgramSpecificImpactWordingResponse = Field(default_factory=ProgramSpecificImpactWordingResponse)
    advisory: Optional[AdvisoryResponse] = None


class BurpNextActionResponse(BaseModel):
    target_url: str = ""
    primary_next_action: str = ""
    request_plan: List[str] = Field(default_factory=list)
    burp_action_checklist: List[str] = Field(default_factory=list)
    suggested_steps: List[str] = Field(default_factory=list)
    labeled_steps: List[LabeledActionResponse] = Field(default_factory=list)
    dashboard_issue: BurpIssueContextResponse = Field(default_factory=BurpIssueContextResponse)
    burp_context_summary: BurpContextSummaryResponse = Field(default_factory=BurpContextSummaryResponse)
    safe_vapt_escalation_steps: List[str] = Field(default_factory=list)
    labeled_safe_vapt_escalation_steps: List[LabeledActionResponse] = Field(default_factory=list)
    escalation_profile: str = ""
    baseline_confirmation: str = ""
    business_impact_expansion_paths: List[str] = Field(default_factory=list)
    required_evidence_for_upgrade: List[str] = Field(default_factory=list)
    stop_conditions: List[str] = Field(default_factory=list)
    likely_severity_promotions: List[str] = Field(default_factory=list)
    scanner_focus: Dict[str, Any] = Field(default_factory=dict)
    repeater_mutation_plan: List[Dict[str, Any]] = Field(default_factory=list)
    repeater_variant_requests: List[Dict[str, Any]] = Field(default_factory=list)
    issue_chain_strategy: List[str] = Field(default_factory=list)
    related_scanner_issues: List[BurpIssueContextResponse] = Field(default_factory=list)
    kb_hints: List[str] = Field(default_factory=list)
    memory_hints: List[str] = Field(default_factory=list)
    preferred_request_ref: str = ""
    reasoning: str = ""
    safe_to_expand: bool = False
    analysis_backend: str = ""
    escalation_ladder: List[str] = Field(default_factory=list)
    reference_links: List[str] = Field(default_factory=list)
    internet_reference_candidates: List[str] = Field(default_factory=list)
    internet_reference_policy: str = ""
    policy_gate: Dict[str, Any] = Field(default_factory=dict)
    execution_safety: Dict[str, Any] = Field(default_factory=dict)
    blocked_expansions: List[str] = Field(default_factory=list)
    next_try_matrix: List[NextTryItemResponse] = Field(default_factory=list)
    one_best_next_step: OneBestNextStepResponse = Field(default_factory=OneBestNextStepResponse)
    reporting_impact_notes: List[str] = Field(default_factory=list)
    official_bcheck_selector: Dict[str, Any] = Field(default_factory=dict)
    issue_family_memory: Dict[str, Any] = Field(default_factory=dict)
    burp_capability_recommendations: List[BurpCapabilityRecommendationResponse] = Field(default_factory=list)
    burp_starter_assets: Dict[str, Any] = Field(default_factory=dict)
    curated_bapp_categories: List[str] = Field(default_factory=list)
    external_tool_recommendations: List[Dict[str, Any]] = Field(default_factory=list)


class BurpRepeaterPlanResponse(BaseModel):
    target_url: str = ""
    dashboard_issue: BurpIssueContextResponse = Field(default_factory=BurpIssueContextResponse)
    related_scanner_issues: List[BurpIssueContextResponse] = Field(default_factory=list)
    burp_context_summary: BurpContextSummaryResponse = Field(default_factory=BurpContextSummaryResponse)
    scanner_focus: Dict[str, Any] = Field(default_factory=dict)
    repeater_mutation_plan: List[Dict[str, Any]] = Field(default_factory=list)
    repeater_variant_requests: List[Dict[str, Any]] = Field(default_factory=list)
    issue_chain_strategy: List[str] = Field(default_factory=list)
    kb_hints: List[str] = Field(default_factory=list)
    memory_hints: List[str] = Field(default_factory=list)
    preferred_request_ref: str = ""
    baseline_confirmation: str = ""
    escalation_profile: str = ""
    analysis_backend: str = ""
    safe_to_expand: bool = False
    policy_gate: Dict[str, Any] = Field(default_factory=dict)
    execution_safety: Dict[str, Any] = Field(default_factory=dict)
    blocked_expansions: List[str] = Field(default_factory=list)
    next_try_matrix: List[NextTryItemResponse] = Field(default_factory=list)
    one_best_next_step: OneBestNextStepResponse = Field(default_factory=OneBestNextStepResponse)
    reporting_impact_notes: List[str] = Field(default_factory=list)
    official_bcheck_selector: Dict[str, Any] = Field(default_factory=dict)
    issue_family_memory: Dict[str, Any] = Field(default_factory=dict)
    burp_capability_recommendations: List[BurpCapabilityRecommendationResponse] = Field(default_factory=list)
    burp_starter_assets: Dict[str, Any] = Field(default_factory=dict)
    curated_bapp_categories: List[str] = Field(default_factory=list)
    external_tool_recommendations: List[Dict[str, Any]] = Field(default_factory=list)


class BurpRepeaterOpenTabResponse(BaseModel):
    tab_name: str = ""
    request_text: str = ""
    summary: str = ""
    expected_signal: str = ""
    request_ref: str = ""
    issue_id: str = ""


class BurpRepeaterOpenResultResponse(BaseModel):
    tab_name: str = ""
    status: str = ""
    detail: str = ""
    tool_name: str = ""


class BurpRepeaterOpenResponse(BaseModel):
    target_url: str = ""
    snapshot_id: str = ""
    workflow_id: str = ""
    workflow_status: str = ""
    dashboard_issue: BurpIssueContextResponse = Field(default_factory=BurpIssueContextResponse)
    related_scanner_issues: List[BurpIssueContextResponse] = Field(default_factory=list)
    preferred_request_ref: str = ""
    analysis_backend: str = ""
    capability_allowed: bool = False
    tool_name: str = ""
    dispatch_requested: bool = True
    opened_count: int = 0
    tabs: List[BurpRepeaterOpenTabResponse] = Field(default_factory=list)
    results: List[BurpRepeaterOpenResultResponse] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


class BurpCompanionConfigActionResponse(BaseModel):
    name: str = ""
    endpoint: str = ""
    purpose: str = ""


class BurpCompanionConfigResponse(BaseModel):
    extension_bundle_endpoint: str = ""
    model_options_endpoint: str = ""
    model_selection_endpoint: str = ""
    actions: List[BurpCompanionConfigActionResponse] = Field(default_factory=list)
    sender_module: str = ""
    notes: List[str] = Field(default_factory=list)


class BurpCompanionExtensionSamplePathsResponse(BaseModel):
    jython: str = ""
    java: str = ""
    montoya: str = ""
    docs: str = ""


class BurpCompanionExtensionResponse(BaseModel):
    name: str = ""
    panel_endpoint: str = ""
    sync_endpoint: str = ""
    open_repeater_plan_endpoint: str = ""
    submit_job_endpoint: str = ""
    capability_recommendations_endpoint: str = ""
    sample_paths: BurpCompanionExtensionSamplePathsResponse = Field(default_factory=BurpCompanionExtensionSamplePathsResponse)
    starter_asset_paths: Dict[str, str] = Field(default_factory=dict)
    recommended_actions: List[str] = Field(default_factory=list)
    selected_message_fields: List[str] = Field(default_factory=list)
    workflow_loop: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


class BurpRepeaterDiffItemResponse(BaseModel):
    tab_name: str = ""
    summary: str = ""
    request_ref: str = ""
    issue_id: str = ""
    status_code: int = 0
    status_transition: str = ""
    header_delta_count: int = 0
    body_length_delta: int = 0
    body_delta_ratio: float = 0.0
    matched_markers: List[str] = Field(default_factory=list)
    expected_signal: str = ""
    expected_signal_matched: bool = False
    mutation_family: str = ""
    score: float = 0.0
    high_signal: bool = False
    reasons: List[str] = Field(default_factory=list)


class BurpRepeaterDiffResponse(BaseModel):
    baseline: Dict[str, Any] = Field(default_factory=dict)
    count: int = 0
    ranked_items: List[BurpRepeaterDiffItemResponse] = Field(default_factory=list)
    best_item: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    advanced_modules: Dict[str, Any] = Field(default_factory=dict)


class BurpIssueWorkflowReadinessResponse(BaseModel):
    ready: bool = False
    status: str = ""
    missing_evidence: List[str] = Field(default_factory=list)


class BurpIssueWorkflowResponse(BaseModel):
    workflow_id: str = ""
    issue_id: str = ""
    issue_name: str = ""
    snapshot_id: str = ""
    request_id: str = ""
    target_url: str = ""
    source_tool: str = ""
    analysis_backend: str = ""
    status: str = ""
    updated_at: str = ""
    created_at: str = ""
    issue_chain_strategy: List[str] = Field(default_factory=list)
    tab_plan: List[BurpRepeaterOpenTabResponse] = Field(default_factory=list)
    ranked_items: List[BurpRepeaterDiffItemResponse] = Field(default_factory=list)
    strongest_delta: Dict[str, Any] = Field(default_factory=dict)
    report_readiness: BurpIssueWorkflowReadinessResponse = Field(default_factory=BurpIssueWorkflowReadinessResponse)
    notes: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    mutation_learning_summary: Dict[str, Any] = Field(default_factory=dict)
    negative_reasoning_summary: Dict[str, Any] = Field(default_factory=dict)
    issue_family_memory: Dict[str, Any] = Field(default_factory=dict)


class BurpBestNextTabResponse(BaseModel):
    workflow_id: str = ""
    issue_id: str = ""
    tab_name: str = ""
    request_text: str = ""
    expected_signal: str = ""
    request_ref: str = ""
    reason: str = ""
    compare_checks: List[str] = Field(default_factory=list)
    score_context: Dict[str, Any] = Field(default_factory=dict)
    learning_hint: str = ""
    ranking_details: Dict[str, Any] = Field(default_factory=dict)


class BurpRepeaterSyncResponse(BaseModel):
    target_url: str = ""
    issue_id: str = ""
    workflow_id: str = ""
    workflow_status: str = ""
    diff: BurpRepeaterDiffResponse = Field(default_factory=BurpRepeaterDiffResponse)
    workflow: BurpIssueWorkflowResponse = Field(default_factory=BurpIssueWorkflowResponse)
    best_next_tab: BurpBestNextTabResponse = Field(default_factory=BurpBestNextTabResponse)
    plan: BurpRepeaterPlanResponse = Field(default_factory=BurpRepeaterPlanResponse)
    summary: str = ""


class BurpPanelStateDiffSummaryResponse(BaseModel):
    count: int = 0
    best_item: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""


class BurpPanelStateResponse(BaseModel):
    target_url: str = ""
    snapshot_id: str = ""
    issue_id: str = ""
    workflow_id: str = ""
    workflow_status: str = ""
    dashboard_issue: BurpIssueContextResponse = Field(default_factory=BurpIssueContextResponse)
    workflow: BurpIssueWorkflowResponse = Field(default_factory=BurpIssueWorkflowResponse)
    best_next_tab: BurpBestNextTabResponse = Field(default_factory=BurpBestNextTabResponse)
    diff_summary: BurpPanelStateDiffSummaryResponse = Field(default_factory=BurpPanelStateDiffSummaryResponse)
    plan: BurpRepeaterPlanResponse = Field(default_factory=BurpRepeaterPlanResponse)
    companion_actions: List[BurpCompanionConfigActionResponse] = Field(default_factory=list)
    guidance_hits: List[GuidanceDbHitResponse] = Field(default_factory=list)
    guidance_merge_policy: List[str] = Field(default_factory=list)
    review_dataset_summary: str = ""
    burp_capability_recommendations: List[BurpCapabilityRecommendationResponse] = Field(default_factory=list)
    official_bcheck_selector: Dict[str, Any] = Field(default_factory=dict)
    issue_family_memory: Dict[str, Any] = Field(default_factory=dict)
    one_best_next_step: OneBestNextStepResponse = Field(default_factory=OneBestNextStepResponse)
    impact_upgrade_planner: ImpactUpgradePlannerResponse = Field(default_factory=ImpactUpgradePlannerResponse)
    reportability_gate: ReportabilityGateResponse = Field(default_factory=ReportabilityGateResponse)
    submission_value_score: SubmissionValueScoreResponse = Field(default_factory=SubmissionValueScoreResponse)
    confidence_to_claim_map: Dict[str, Any] = Field(default_factory=dict)
    negative_reasoning_summary: Dict[str, Any] = Field(default_factory=dict)
    advanced_modules: Dict[str, Any] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)


class ConfidenceCalibrationResponse(BaseModel):
    level: str = ""
    score: float = 0.0
    target_rule: Dict[str, Any] = Field(default_factory=dict)
    reasons: List[str] = Field(default_factory=list)
    missing_artifacts: List[str] = Field(default_factory=list)


class EvidenceGateResponse(BaseModel):
    max_allowed_severity: str = ""
    reasons: List[str] = Field(default_factory=list)
    thresholds: Dict[str, Any] = Field(default_factory=dict)


class SeverityAssessmentResponse(BaseModel):
    severity: str = ""
    confidence: float = 0.0
    candidate_taxonomy: str = ""
    rationale: str = ""
    promotion_triggers: List[str] = Field(default_factory=list)
    downgrade_reasons: List[str] = Field(default_factory=list)
    evidence_gate: EvidenceGateResponse = Field(default_factory=EvidenceGateResponse)
    confidence_calibration: ConfidenceCalibrationResponse = Field(default_factory=ConfidenceCalibrationResponse)
    reportability_gate: ReportabilityGateResponse = Field(default_factory=ReportabilityGateResponse)
    submission_value_score: SubmissionValueScoreResponse = Field(default_factory=SubmissionValueScoreResponse)
    confidence_to_claim_map: Dict[str, Any] = Field(default_factory=dict)


class BrowserVerificationAppendixResponse(BaseModel):
    allowed: bool = False
    verification_goal: str = ""
    allowed_workflows: List[str] = Field(default_factory=list)
    suggested_steps: List[str] = Field(default_factory=list)
    stop_conditions: List[str] = Field(default_factory=list)


class McpRuntimeStatusResponse(BaseModel):
    enabled: bool
    transport: str = ""
    tool_name: str = ""
    timeout_seconds: int = 0
    protocol_version: str = ""
    status: str = ""
    detail: str = ""
    command: str = ""
    url: str = ""
    working_directory: str = ""
    server_name: str = ""
    server_version: str = ""
    available_tools: List[str] = Field(default_factory=list)
    read_only_only: bool = True
    capability_map: Dict[str, Any] = Field(default_factory=dict)
    permitted_tools: List[str] = Field(default_factory=list)
    blocked_tools: List[str] = Field(default_factory=list)
    denied_capabilities: List[str] = Field(default_factory=list)


class BurpExporterConfigResponse(BaseModel):
    contract_version: str = ""
    bridge_endpoint: str = ""
    required_fields: List[str] = Field(default_factory=list)
    default_flags: Dict[str, Any] = Field(default_factory=dict)
    source_tool_map: Dict[str, str] = Field(default_factory=dict)
    macro_template: Dict[str, Any] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)


class BurpMcpCapabilityEntryResponse(BaseModel):
    tool_name: str = ""
    allowed: bool = False
    mode: str = ""


class BurpMcpCapabilitiesResponse(BaseModel):
    transport: str = ""
    timeout_seconds: int = 0
    protocol_version: str = ""
    url: str = ""
    command: str = ""
    working_directory: str = ""
    server_name: str = ""
    server_version: str = ""
    available_tools: List[str] = Field(default_factory=list)
    read_only_only: bool = True
    capability_map: Dict[str, BurpMcpCapabilityEntryResponse] = Field(default_factory=dict)
    permitted_tools: List[str] = Field(default_factory=list)
    blocked_tools: List[str] = Field(default_factory=list)
    denied_capabilities: List[str] = Field(default_factory=list)


class BurpMcpCapabilityRequest(BaseModel):
    capability: str
    count: int = 8
    offset: int = 0
    query: str = ""
    payload: Dict[str, Any] = Field(default_factory=dict)


class BurpMcpCapabilityResponse(BaseModel):
    capability: str = ""
    tool_name: str = ""
    arguments: Dict[str, Any] = Field(default_factory=dict)
    content_text: str = ""
    structured_content: Dict[str, Any] = Field(default_factory=dict)
    available_tools: List[str] = Field(default_factory=list)
    server_name: str = ""
    server_version: str = ""
    protocol_version: str = ""


class BurpSessionSnapshotResponse(BaseModel):
    snapshot_id: str = ""
    created_at: str = ""
    target_url: str = ""
    http_method: str = ""
    source_tool: str = ""
    use_burp_mcp_context: bool = False
    issue_context: BurpIssueContextResponse = Field(default_factory=BurpIssueContextResponse)
    scanner_details: Dict[str, Any] = Field(default_factory=dict)
    proxy_history: BurpEntriesResponse = Field(default_factory=BurpEntriesResponse)
    repeater_context: RepeaterRequestResponse = Field(default_factory=RepeaterRequestResponse)
    project_config: BurpProjectConfigResponse = Field(default_factory=BurpProjectConfigResponse)
    active_editor_request: str = ""
    regex_history_matches: List[Dict[str, Any]] = Field(default_factory=list)
    collaborator_interactions: List[Dict[str, Any]] = Field(default_factory=list)
    mcp_summary: Dict[str, Any] = Field(default_factory=dict)
    evidence_bundle: List[Dict[str, Any]] = Field(default_factory=list)
    analysis_payload: Dict[str, Any] = Field(default_factory=dict)


class OllamaRuntimeStatusResponse(BaseModel):
    enabled: bool
    configured_url: str = ""
    model: str = ""
    vision_model: str = ""
    timeout_seconds: int = 0
    status: str = ""
    detail: str = ""
    candidate_urls: List[str] = Field(default_factory=list)
    tag_probe_urls: List[str] = Field(default_factory=list)
    selected_endpoint: str = ""
    detected_models: List[str] = Field(default_factory=list)


class RuntimeHealthResponse(BaseModel):
    configured_provider_order: List[str] = Field(default_factory=list)
    active_provider_order: List[str] = Field(default_factory=list)
    context_priority: Dict[str, Any] = Field(default_factory=dict)
    burp_mcp: McpRuntimeStatusResponse
    mcp: McpRuntimeStatusResponse
    ollama: OllamaRuntimeStatusResponse


class RuntimeReadinessCheckResponse(BaseModel):
    name: str = ""
    status: str = ""
    detail: str = ""


class RuntimeReadinessResponse(BaseModel):
    request_id: str = ""
    status: str = ""
    summary: str = ""
    recommended_analysis_endpoint: str = ""
    runtime_ready: bool = False
    input_ready: bool = False
    checks: List[RuntimeReadinessCheckResponse] = Field(default_factory=list)
    blockers: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    burp_context_summary: BurpContextSummaryResponse = Field(default_factory=BurpContextSummaryResponse)
    project_config: BurpProjectConfigResponse = Field(default_factory=BurpProjectConfigResponse)
    execution_safety: Dict[str, Any] = Field(default_factory=dict)
    runtime_health: RuntimeHealthResponse
    context_priority: Dict[str, Any] = Field(default_factory=dict)
    labeled_next_steps: List[LabeledActionResponse] = Field(default_factory=list)


class ProviderDiagnosticRecordResponse(BaseModel):
    job_id: str = ""
    request_id: str = ""
    created_at: str = ""
    target_url: str = ""
    status: str = ""
    analysis_backend: str = ""
    fallback_used: bool = False
    fallback_reason: str = ""
    provider_trace: List[str] = Field(default_factory=list)
    provider_failover: ProviderFailoverResponse = Field(default_factory=ProviderFailoverResponse)


class ProviderDiagnosticsHistoryResponse(BaseModel):
    total_matches: int = 0
    count: int = 0
    limit: int = 0
    cursor: int = 0
    next_cursor: Optional[int] = None
    provider_status_counts: Dict[str, int] = Field(default_factory=dict)
    backend_counts: Dict[str, int] = Field(default_factory=dict)
    items: List[ProviderDiagnosticRecordResponse] = Field(default_factory=list)


class AnalysisJobAcceptedResponse(BaseModel):
    job_id: str
    request_id: str = ""
    snapshot_id: str = ""
    status: str
    status_message: str
    estimated_duration: str
    complexity: str
    recommendation: str


class AnalysisJobStatusResponse(BaseModel):
    job_id: str
    request_id: str = ""
    snapshot_id: str = ""
    status: str
    status_message: str
    estimated_duration: str
    complexity: str
    recommendation: str
    result: Optional[AdvisoryResponse] = None
    analysis_run: Optional[AnalysisRunResponse] = None
    error: Optional[str] = None


class HistoryRecordResponse(BaseModel):
    job_id: str
    request_id: str = ""
    snapshot_id: str = ""
    status: str
    created_at: str
    target_url: str
    batch_id: str
    batch_index: int
    batch_total: int
    selected_profile: str = ""
    review_scope_include_classes: List[str] = Field(default_factory=list)
    review_scope_exclude_classes: List[str] = Field(default_factory=list)
    result: Optional[AdvisoryResponse] = None
    analysis_run: Optional[AnalysisRunResponse] = None
    error: Optional[str] = None


class FeedbackRequest(BaseModel):
    job_id: str
    label: str
    notes: Optional[str] = ""


class FeedbackResponse(BaseModel):
    job_id: str
    label: str
    notes: str
    recorded_at: str
    related_feedback_count: int


class GuidanceFeedbackRequest(BaseModel):
    job_id: str
    label: str
    guidance_pack_ids: List[str] = Field(default_factory=list)
    notes: str = ""


class BurpAssetFeedbackRequest(BaseModel):
    asset_type: str
    asset_id: str
    label: str
    target_url: str = ""
    vuln_class: str = ""
    selected_profile: str = ""
    program_platform: str = ""
    program_policy_template: str = ""
    notes: str = ""
    job_id: str = ""
    request_id: str = ""


class BurpAssetFeedbackResponse(BaseModel):
    asset_type: str = ""
    asset_id: str = ""
    label: str = ""
    target_url: str = ""
    vuln_class: str = ""
    memory_partition_key: str = ""
    notes: str = ""
    job_id: str = ""
    request_id: str = ""
    created_at: str = ""


class GuidanceFeedbackResponse(BaseModel):
    job_id: str = ""
    label: str = ""
    guidance_pack_ids: List[str] = Field(default_factory=list)


class HypothesisStatusRequest(BaseModel):
    job_id: str
    hypothesis_id: str
    status: str
    notes: Optional[str] = ""


class HypothesisStatusResponse(BaseModel):
    job_id: str
    hypothesis_id: str
    status: str
    notes: str = ""
    updated_at: str = ""
    summary: str = ""


class PhaseSnapshotResponse(BaseModel):
    job_id: str = ""
    request_id: str = ""
    created_at: str = ""
    target_url: str = ""
    phase: str = ""
    result: Dict[str, Any] = Field(default_factory=dict)
    input_context: Dict[str, Any] = Field(default_factory=dict)


class PhaseHistoryResponse(BaseModel):
    job_id: str = ""
    request_id: str = ""
    phase: str = ""
    count: int = 0
    items: List[PhaseSnapshotResponse] = Field(default_factory=list)


class AnalysisReasoningEvidenceResponse(BaseModel):
    source: str = ""
    evidence_type: str = ""
    summary: str = ""
    confidence: float = 0.0


class AnalysisReasoningPhaseResponse(BaseModel):
    phase: str = ""
    summary: str = ""


class AnalysisReasoningResponse(BaseModel):
    job_id: str
    request_id: str = ""
    target_url: str = ""
    top_hypothesis: Dict[str, Any] = Field(default_factory=dict)
    phase_highlights: List[AnalysisReasoningPhaseResponse] = Field(default_factory=list)
    key_evidence: List[AnalysisReasoningEvidenceResponse] = Field(default_factory=list)
    confidence_drivers: List[str] = Field(default_factory=list)
    downgrade_reasons: List[str] = Field(default_factory=list)
    next_decision: Dict[str, Any] = Field(default_factory=dict)


class BurpPayloadContractResponse(BaseModel):
    contract_version: str
    description: str = ""
    transport: Dict[str, Any] = Field(default_factory=dict)
    top_level_fields: Dict[str, List[str]] = Field(default_factory=dict)
    phase_intent: Dict[str, List[str]] = Field(default_factory=dict)
    issue_fields: Dict[str, List[str]] = Field(default_factory=dict)
    entry_fields: Dict[str, List[str]] = Field(default_factory=dict)
    examples: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class BurpNormalizedPayloadResponse(BaseModel):
    raw_request: str = ""
    raw_response: str = ""
    target_url: str = ""
    http_method: str = ""
    source_tool: str = ""
    use_burp_mcp_context: bool = False
    baseline_response_text: str = ""
    issue_workflow_notes: List[str] = Field(default_factory=list)
    investigation_notebook_text: str = ""
    repeater_variant_observations: List[Dict[str, Any]] = Field(default_factory=list)
    burp_dashboard_issue: Dict[str, Any] = Field(default_factory=dict)
    burp_related_scanner_issues: List[Dict[str, Any]] = Field(default_factory=list)
    proxy_history_entries: List[Dict[str, Any]] = Field(default_factory=list)
    logger_entries: List[Dict[str, Any]] = Field(default_factory=list)
    repeater_requests: List[Dict[str, Any]] = Field(default_factory=list)
    project_config_snapshot: Dict[str, Any] = Field(default_factory=dict)


class BurpExportNextStepResponse(BaseModel):
    api_endpoint: str = ""
    mcp_tool: str = ""
    notes: List[str] = Field(default_factory=list)


class BurpExportSummaryResponse(BaseModel):
    target_url: str = ""
    http_method: str = ""
    source_tool: str = ""
    dashboard_issue_found: bool = False
    proxy_history_count: int = 0
    logger_entry_count: int = 0
    repeater_request_count: int = 0
    enabled_tool_count: int = 0


class BurpPrepareExportResponse(BaseModel):
    contract_version: str = ""
    payload: BurpNormalizedPayloadResponse
    summary: BurpExportSummaryResponse
    next_step: BurpExportNextStepResponse
    exporter: Dict[str, Any] = Field(default_factory=dict)


class HistoryRecordPageResponse(BaseModel):
    cursor: int = 0
    limit: int = 0
    total: int = 0
    count: int = 0
    next_cursor: Optional[int] = None
    items: List[HistoryRecordResponse] = Field(default_factory=list)


class StructuredReportResponse(BaseModel):
    job_id: str
    request_id: str = ""
    snapshot_id: str = ""
    title: str = ""
    summary: str = ""
    primary_next_action: str = ""
    reporting_checklist: List[str] = Field(default_factory=list)
    labeled_reporting_steps: List[LabeledActionResponse] = Field(default_factory=list)
    hypothesis_summaries: List[ReportEvidenceHypothesisResponse] = Field(default_factory=list)
    evidence_artifacts: List[ReportEvidenceArtifactResponse] = Field(default_factory=list)
    impact_assessment: Dict[str, Any] = Field(default_factory=dict)
    validation_assessment: Dict[str, Any] = Field(default_factory=dict)
    analysis_backend: str = ""
    fallback_used: bool = False
    source_links: List[str] = Field(default_factory=list)
    next_decision: Dict[str, Any] = Field(default_factory=dict)
    escalation_guidance: Dict[str, Any] = Field(default_factory=dict)
    impact_upgrade_planner: ImpactUpgradePlannerResponse = Field(default_factory=ImpactUpgradePlannerResponse)
    finding_to_impact_template: FindingToImpactTemplateResponse = Field(default_factory=FindingToImpactTemplateResponse)
    reportability_gate: ReportabilityGateResponse = Field(default_factory=ReportabilityGateResponse)
    submission_value_score: SubmissionValueScoreResponse = Field(default_factory=SubmissionValueScoreResponse)
    program_specific_impact_wording: ProgramSpecificImpactWordingResponse = Field(default_factory=ProgramSpecificImpactWordingResponse)
    confidence_to_claim_map: Dict[str, Any] = Field(default_factory=dict)
    burp_session_snapshot: Dict[str, Any] = Field(default_factory=dict)


class BugBountySubmissionResponse(BaseModel):
    job_id: str
    request_id: str = ""
    snapshot_id: str = ""
    platform: str = ""
    template_name: str = ""
    title: str = ""
    target_url: str = ""
    summary: str = ""
    severity_assessment: SeverityAssessmentResponse = Field(default_factory=SeverityAssessmentResponse)
    validation_status: str = ""
    reportability: str = ""
    reproduction_steps: List[str] = Field(default_factory=list)
    impact_statement: str = ""
    evidence_highlights: List[str] = Field(default_factory=list)
    submission_notes: List[str] = Field(default_factory=list)
    policy_alignment: List[str] = Field(default_factory=list)
    browser_verification_appendix: BrowserVerificationAppendixResponse = Field(default_factory=BrowserVerificationAppendixResponse)
    escalation_guidance: Dict[str, Any] = Field(default_factory=dict)
    impact_upgrade_planner: ImpactUpgradePlannerResponse = Field(default_factory=ImpactUpgradePlannerResponse)
    finding_to_impact_template: FindingToImpactTemplateResponse = Field(default_factory=FindingToImpactTemplateResponse)
    reportability_gate: ReportabilityGateResponse = Field(default_factory=ReportabilityGateResponse)
    submission_value_score: SubmissionValueScoreResponse = Field(default_factory=SubmissionValueScoreResponse)
    program_specific_impact_wording: ProgramSpecificImpactWordingResponse = Field(default_factory=ProgramSpecificImpactWordingResponse)
    confidence_to_claim_map: Dict[str, Any] = Field(default_factory=dict)
    burp_session_snapshot: Dict[str, Any] = Field(default_factory=dict)
    markdown: str = ""


class ImpactUpgradePlanResponse(BaseModel):
    planner: ImpactUpgradePlannerResponse = Field(default_factory=ImpactUpgradePlannerResponse)
    finding_to_impact_template: FindingToImpactTemplateResponse = Field(default_factory=FindingToImpactTemplateResponse)
    reportability_gate: ReportabilityGateResponse = Field(default_factory=ReportabilityGateResponse)
    submission_value_score: SubmissionValueScoreResponse = Field(default_factory=SubmissionValueScoreResponse)
    program_specific_impact_wording: ProgramSpecificImpactWordingResponse = Field(default_factory=ProgramSpecificImpactWordingResponse)
    confidence_to_claim_map: Dict[str, Any] = Field(default_factory=dict)


class OperatorReviewResponse(BaseModel):
    job_id: str = ""
    request_id: str = ""
    snapshot_id: str = ""
    platform: str = ""
    title: str = ""
    strongest_evidence: List[str] = Field(default_factory=list)
    weakest_assumption: str = ""
    next_best_allowed_step: str = ""
    reportability_gate: ReportabilityGateResponse = Field(default_factory=ReportabilityGateResponse)
    submission_value_score: SubmissionValueScoreResponse = Field(default_factory=SubmissionValueScoreResponse)
    confidence_to_claim_map: Dict[str, Any] = Field(default_factory=dict)
    program_specific_impact_wording: ProgramSpecificImpactWordingResponse = Field(default_factory=ProgramSpecificImpactWordingResponse)
    summary: str = ""


class SubmissionRegressionResponse(BaseModel):
    count: int = 0
    items: List[Dict[str, Any]] = Field(default_factory=list)
    review_examples: List[Dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


class SubmissionRegressionImportRequest(BaseModel):
    vuln_class: str = ""
    outcome: str = ""
    platform: str = ""
    limit: int = 100


class SubmissionRegressionImportResponse(BaseModel):
    imported_count: int = 0
    skipped_count: int = 0
    items: List[Dict[str, Any]] = Field(default_factory=list)
    skipped_job_ids: List[str] = Field(default_factory=list)
    summary: str = ""


class BCheckResultIngestRequest(AssessmentRequest):
    raw_request: Optional[str] = ""
    selected_bcheck: Dict[str, Any] = Field(default_factory=dict)
    outcome_label: str
    notes: str = ""
    evidence_signal: str = ""
    issue_id: str = ""


class BCheckResultIngestResponse(BaseModel):
    recorded: bool = False
    result_label: str = ""
    selected_bcheck: OfficialBCheckSelectionResponse = Field(default_factory=OfficialBCheckSelectionResponse)
    issue_family_memory: Dict[str, Any] = Field(default_factory=dict)
    one_best_next_step: OneBestNextStepResponse = Field(default_factory=OneBestNextStepResponse)
    summary: str = ""


class WordingComparisonResponse(BaseModel):
    vuln_class: str = ""
    platform: str = ""
    too_vague: List[str] = Field(default_factory=list)
    too_strong: List[str] = Field(default_factory=list)
    just_right: List[str] = Field(default_factory=list)
    summary: str = ""


class RuntimeBenchmarkResponse(BaseModel):
    window_count: int = 0
    latency_by_model: Dict[str, Any] = Field(default_factory=dict)
    memory_by_model: Dict[str, Any] = Field(default_factory=dict)
    fallback_frequency: Dict[str, Any] = Field(default_factory=dict)
    average_context_size: Dict[str, Any] = Field(default_factory=dict)
    suggested_step_success_rate: Dict[str, Any] = Field(default_factory=dict)
    rollout_comparison: Dict[str, Any] = Field(default_factory=dict)
    benchmark_snapshots: Dict[str, Any] = Field(default_factory=dict)
    model_matrix: Dict[str, Any] = Field(default_factory=dict)
    diagnostics: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""


class EvidenceBundleResponse(BaseModel):
    job_id: str = ""
    request_id: str = ""
    snapshot_id: str = ""
    target_url: str = ""
    request_response: Dict[str, Any] = Field(default_factory=dict)
    burp_snapshot: Dict[str, Any] = Field(default_factory=dict)
    best_diff: Dict[str, Any] = Field(default_factory=dict)
    planner: ImpactUpgradePlannerResponse = Field(default_factory=ImpactUpgradePlannerResponse)
    report_draft: Dict[str, Any] = Field(default_factory=dict)
    guidance_hits: List[GuidanceDbHitResponse] = Field(default_factory=list)


class BurpDirectSubmitConfigResponse(BaseModel):
    submit_endpoint: str = ""
    snapshot_endpoint: str = ""
    open_repeater_plan_endpoint: str = ""
    companion_config_endpoint: str = ""
    companion_extension_endpoint: str = ""
    capability_recommendations_endpoint: str = ""
    bcheck_result_endpoint: str = ""
    model_options_endpoint: str = ""
    model_selection_endpoint: str = ""
    panel_state_endpoint: str = ""
    required_fields: List[str] = Field(default_factory=list)
    default_payload: Dict[str, Any] = Field(default_factory=dict)
    python_sender_template: str = ""
    python_repeater_template: str = ""
    python_sync_template: str = ""
    python_panel_template: str = ""
    python_bcheck_result_template: str = ""
    notes: List[str] = Field(default_factory=list)


class AuditEventResponse(BaseModel):
    timestamp: str = ""
    event_type: str = ""
    previous_hash: str = ""
    entry_hash: str = ""
    data: Dict[str, Any] = Field(default_factory=dict)


class AuditEventPageResponse(BaseModel):
    cursor: int = 0
    limit: int = 0
    total: int = 0
    count: int = 0
    next_cursor: Optional[int] = None
    items: List[AuditEventResponse] = Field(default_factory=list)


AdvisoryResponse.model_rebuild()
ImpactAssessmentResponse.model_rebuild()
AnalyzeEndpointResponse = Union[AdvisoryResponse, AnalysisJobAcceptedResponse]


@app.post("/api/analyze", response_model=AnalyzeEndpointResponse, deprecated=True)
async def analyze_endpoint(payload: AssessmentRequest, request: Request, response: Response, legacy_sync: bool = False):
    payload = _payload_with_request_id(payload, request)
    try:
        _apply_analyze_deprecation_headers(response)
        if not legacy_sync:
            append_audit_event("analysis_sync_redirected", {
                "request_id": payload.request_id,
                "target_url": payload.target_url,
                "http_method": payload.http_method,
            })
            job = job_manager.submit(payload)
            response.status_code = 202
            return AnalysisJobAcceptedResponse(**job)

        append_audit_event("analysis_request", {
            "request_id": payload.request_id,
            "target_url": payload.target_url,
            "http_method": payload.http_method,
            "annotations": payload.annotations,
            "privacy_mode_override": payload.privacy_mode_override,
            "legacy_sync": True,
        })
        result = analyze_payload(payload)
        append_audit_event("analysis_result", {
            "request_id": payload.request_id,
            "target_url": payload.target_url,
            "http_method": payload.http_method,
            "privacy_mode_override": payload.privacy_mode_override,
            "vuln_count": len(result.get("potential_vulnerabilities", [])),
            "tags": result.get("nuclei_tags", ""),
            "legacy_sync": True,
        })
        result.setdefault("request_id", payload.request_id)
        return AdvisoryResponse(**result)
    except Exception as exc:
        _handle_internal_error(request, "AI Bridge analysis failed.", exc)


@app.post("/api/hypotheses/summary", response_model=HypothesisSummaryResponse)
async def summarize_hypotheses_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return HypothesisSummaryResponse(**summarize_hypotheses(payload))
    except Exception as exc:
        _handle_internal_error(request, "Hypothesis summary failed.", exc)


@app.post("/api/hypotheses/validate", response_model=HypothesisValidationResponse)
async def validate_hypothesis_endpoint(payload: AssessmentRequest, request: Request, hypothesis_id: str = ""):
    payload = _payload_with_request_id(payload, request)
    try:
        return HypothesisValidationResponse(**validate_hypothesis(payload, hypothesis_id=hypothesis_id or None))
    except Exception as exc:
        _handle_internal_error(request, "Hypothesis validation failed.", exc)


@app.post("/api/impact/rank", response_model=ImpactAssessmentResponse)
async def rank_impact_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return ImpactAssessmentResponse(**rank_impact_paths(payload))
    except Exception as exc:
        _handle_internal_error(request, "Impact ranking failed.", exc)


@app.post("/api/impact/upgrade-plan", response_model=ImpactUpgradePlanResponse)
async def impact_upgrade_plan_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        validation = validate_hypothesis(payload)
        impact = rank_impact_paths(payload)
        severity = assess_submission_severity(payload, validation=validation, impact=impact)
        claim_map = build_confidence_to_claim_map(
            ((impact.get("dashboard_issue") or {}).get("vuln_hint") or "general"),
            confidence_level=((severity.get("confidence_calibration") or {}).get("level") or "low"),
            validation=validation,
            impact=impact,
        )
        return ImpactUpgradePlanResponse(
            planner=impact.get("impact_upgrade_planner") or {},
            finding_to_impact_template=impact.get("finding_to_impact_template") or {},
            reportability_gate=impact.get("reportability_gate") or {},
            submission_value_score=severity.get("submission_value_score") or {},
            program_specific_impact_wording=build_program_specific_impact_wording(
                payload.program_policy_template or payload.program_platform or "",
                ((impact.get("dashboard_issue") or {}).get("vuln_hint") or "general"),
                impact,
            ),
            confidence_to_claim_map=claim_map,
        )
    except Exception as exc:
        _handle_internal_error(request, "Impact upgrade planning failed.", exc)


@app.post("/api/burp/next-action", response_model=BurpNextActionResponse)
async def next_burp_action_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpNextActionResponse(**next_burp_action(payload))
    except Exception as exc:
        _handle_internal_error(request, "Burp action planning failed.", exc)


@app.post("/api/burp/capability-recommendations", response_model=Dict[str, Any])
async def burp_capability_recommendations_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        impact = rank_impact_paths(payload)
        return recommend_burp_capabilities(payload, impact=impact)
    except Exception as exc:
        _handle_internal_error(request, "Burp capability recommendations failed.", exc)


@app.post("/api/burp/repeater-plan", response_model=BurpRepeaterPlanResponse)
async def burp_repeater_plan_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpRepeaterPlanResponse(**burp_repeater_plan(payload))
    except Exception as exc:
        _handle_internal_error(request, "Burp repeater planning failed.", exc)


@app.post("/api/burp/open-repeater-plan", response_model=BurpRepeaterOpenResponse)
async def burp_open_repeater_plan_endpoint(payload: AssessmentRequest, request: Request, dispatch: bool = True):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpRepeaterOpenResponse(**open_repeater_plan(payload, dispatch=dispatch))
    except Exception as exc:
        _handle_internal_error(request, "Burp repeater tab dispatch failed.", exc)


@app.post("/api/burp/issue-context", response_model=BurpIssueContextResponse)
async def burp_issue_context_endpoint(payload: BurpContextRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpIssueContextResponse(**get_dashboard_issue_context(payload))
    except Exception as exc:
        _handle_internal_error(request, "Burp issue context extraction failed.", exc)


@app.post("/api/burp/proxy-history", response_model=BurpEntriesResponse)
async def burp_proxy_history_endpoint(payload: BurpContextRequest, request: Request, limit: int = 8):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpEntriesResponse(**get_recent_proxy_history(payload, limit=max(1, min(limit, 12))))
    except Exception as exc:
        _handle_internal_error(request, "Burp proxy history extraction failed.", exc)


@app.post("/api/burp/logger-deltas", response_model=BurpEntriesResponse)
async def burp_logger_deltas_endpoint(payload: BurpContextRequest, request: Request, limit: int = 8):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpEntriesResponse(**get_logger_deltas(payload, limit=max(1, min(limit, 12))))
    except Exception as exc:
        _handle_internal_error(request, "Burp logger extraction failed.", exc)


@app.post("/api/burp/repeater-request", response_model=RepeaterRequestResponse)
async def burp_repeater_request_endpoint(payload: BurpContextRequest, request: Request, limit: int = 3):
    payload = _payload_with_request_id(payload, request)
    try:
        return RepeaterRequestResponse(**get_repeater_request(payload, limit=max(1, min(limit, 6))))
    except Exception as exc:
        _handle_internal_error(request, "Burp repeater extraction failed.", exc)


@app.post("/api/burp/project-config", response_model=BurpProjectConfigResponse)
async def burp_project_config_endpoint(payload: BurpContextRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpProjectConfigResponse(**get_project_config_snapshot(payload))
    except Exception as exc:
        _handle_internal_error(request, "Burp project configuration extraction failed.", exc)


@app.get("/api/burp/exporter-config", response_model=BurpExporterConfigResponse)
async def burp_exporter_config_endpoint(request: Request):
    try:
        return BurpExporterConfigResponse(**build_burp_exporter_config())
    except Exception as exc:
        _handle_internal_error(request, "Burp exporter configuration failed.", exc)


@app.get("/api/burp/direct-submit-config", response_model=BurpDirectSubmitConfigResponse)
async def burp_direct_submit_config_endpoint(request: Request):
    try:
        return BurpDirectSubmitConfigResponse(**build_burp_direct_submit_config())
    except Exception as exc:
        _handle_internal_error(request, "Burp direct submit configuration failed.", exc)


@app.get("/api/burp/companion-config", response_model=BurpCompanionConfigResponse)
async def burp_companion_config_endpoint(request: Request):
    try:
        return BurpCompanionConfigResponse(**build_burp_companion_config())
    except Exception as exc:
        _handle_internal_error(request, "Burp companion configuration failed.", exc)


@app.get("/api/burp/companion-extension", response_model=BurpCompanionExtensionResponse)
async def burp_companion_extension_endpoint(request: Request):
    try:
        return BurpCompanionExtensionResponse(**build_burp_companion_extension_bundle())
    except Exception as exc:
        _handle_internal_error(request, "Burp companion extension bundle failed.", exc)


@app.get("/api/burp/mcp-capabilities", response_model=BurpMcpCapabilitiesResponse)
async def burp_mcp_capabilities_endpoint(request: Request):
    try:
        return BurpMcpCapabilitiesResponse(**inspect_burp_mcp_capabilities())
    except Exception as exc:
        _handle_internal_error(request, "Burp MCP capability inspection failed.", exc)


@app.post("/api/burp/mcp-capability", response_model=BurpMcpCapabilityResponse)
async def burp_mcp_capability_endpoint(payload: BurpMcpCapabilityRequest, request: Request):
    try:
        target_url = ""
        if payload.payload:
            target_url = str(payload.payload.get("target_url") or payload.payload.get("url") or "").strip()
        result = call_burp_mcp_capability(
            payload.capability,
            count=payload.count,
            offset=payload.offset,
            query=payload.query,
            target_url=target_url,
            payload=payload.payload,
        )
        return BurpMcpCapabilityResponse(**result)
    except MCPError as exc:
        raise HTTPException(
            status_code=400,
            detail={"message": str(exc), "request_id": _request_id(request)},
        )
    except Exception as exc:
        _handle_internal_error(request, "Burp MCP capability call failed.", exc)


@app.get("/api/burp/payload-contract", response_model=BurpPayloadContractResponse)
async def burp_payload_contract_endpoint(request: Request):
    try:
        return BurpPayloadContractResponse(**build_burp_payload_contract())
    except Exception as exc:
        _handle_internal_error(request, "Burp payload contract failed.", exc)


@app.post("/api/burp/normalize-payload", response_model=BurpNormalizedPayloadResponse)
async def burp_normalize_payload_endpoint(payload: Dict[str, Any], request: Request):
    try:
        return BurpNormalizedPayloadResponse(**normalize_burp_payload(payload))
    except Exception as exc:
        _handle_internal_error(request, "Burp payload normalization failed.", exc)


@app.post("/api/burp/prepare-export", response_model=BurpPrepareExportResponse)
async def burp_prepare_export_endpoint(payload: Dict[str, Any], request: Request):
    try:
        return BurpPrepareExportResponse(**prepare_burp_export(payload))
    except Exception as exc:
        _handle_internal_error(request, "Burp export preparation failed.", exc)


@app.post("/api/burp/session-snapshot", response_model=BurpSessionSnapshotResponse)
async def burp_session_snapshot_endpoint(payload: BurpContextRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        snapshot = build_burp_session_snapshot(payload)
        return BurpSessionSnapshotResponse(**snapshot)
    except Exception as exc:
        _handle_internal_error(request, "Burp session snapshot failed.", exc)


@app.post("/api/burp/repeater-diff-score", response_model=BurpRepeaterDiffResponse)
async def burp_repeater_diff_score_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpRepeaterDiffResponse(**score_repeater_diffs(payload, plan=burp_repeater_plan(payload)))
    except Exception as exc:
        _handle_internal_error(request, "Burp repeater diff scoring failed.", exc)


@app.post("/api/burp/repeater-sync", response_model=BurpRepeaterSyncResponse)
async def burp_repeater_sync_endpoint(payload: AssessmentRequest, request: Request, include_plan: bool = True):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpRepeaterSyncResponse(**sync_repeater_observations(payload, include_plan=include_plan))
    except Exception as exc:
        _handle_internal_error(request, "Burp repeater sync failed.", exc)


@app.post("/api/burp/panel-state", response_model=BurpPanelStateResponse)
async def burp_panel_state_endpoint(
    payload: AssessmentRequest,
    request: Request,
    issue_id: str = "",
    snapshot_id: str = "",
    workflow_id: str = "",
    include_plan: bool = True,
    include_companion_actions: bool = True,
):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpPanelStateResponse(
            **build_burp_panel_state(
                payload,
                issue_id=issue_id,
                snapshot_id=snapshot_id,
                workflow_id=workflow_id,
                include_plan=include_plan,
                include_companion_actions=include_companion_actions,
            )
        )
    except Exception as exc:
        _handle_internal_error(request, "Burp panel state refresh failed.", exc)


@app.post("/api/burp/issues/workflow", response_model=BurpIssueWorkflowResponse)
async def burp_issue_workflow_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpIssueWorkflowResponse(**build_workflow_from_observations(payload, plan=burp_repeater_plan(payload)))
    except Exception as exc:
        _handle_internal_error(request, "Burp issue workflow update failed.", exc)


@app.get("/api/burp/issues/workflow/{issue_id}", response_model=BurpIssueWorkflowResponse)
async def burp_issue_workflow_lookup_endpoint(issue_id: str, snapshot_id: str = "", workflow_id: str = ""):
    workflow = lookup_issue_workflow(issue_id=issue_id, snapshot_id=snapshot_id, workflow_id=workflow_id)
    if not workflow:
        raise HTTPException(status_code=404, detail={"message": "Issue workflow not found.", "issue_id": issue_id})
    return BurpIssueWorkflowResponse(**workflow)


@app.post("/api/burp/best-next-tab", response_model=BurpBestNextTabResponse)
async def burp_best_next_tab_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return BurpBestNextTabResponse(**best_next_tab(payload, plan=burp_repeater_plan(payload)))
    except Exception as exc:
        _handle_internal_error(request, "Burp best-next-tab selection failed.", exc)


@app.post("/api/burp/submit-job", response_model=AnalysisJobAcceptedResponse, status_code=202)
async def burp_submit_job_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        normalized_payload = normalize_burp_payload_contract(payload)
        normalized_payload["use_burp_mcp_context"] = True
        normalized_payload["source_tool"] = normalized_payload.get("source_tool") or payload.source_tool or "repeater"
        snapshot = build_burp_session_snapshot({
            **normalized_payload,
        })
        payload = payload.model_copy(update={
            "use_burp_mcp_context": True,
            "source_tool": normalized_payload.get("source_tool") or payload.source_tool or "repeater",
            "snapshot_id": snapshot.get("snapshot_id", ""),
            "raw_request": payload.raw_request or ((snapshot.get("analysis_payload") or {}).get("raw_request") or ""),
            "target_url": payload.target_url or ((snapshot.get("analysis_payload") or {}).get("target_url") or ""),
            "http_method": payload.http_method or ((snapshot.get("analysis_payload") or {}).get("http_method") or ""),
            "burp_dashboard_issue": normalized_payload.get("burp_dashboard_issue") or payload.burp_dashboard_issue,
            "burp_related_scanner_issues": normalized_payload.get("burp_related_scanner_issues") or payload.burp_related_scanner_issues,
        })
        append_audit_event("burp_direct_submit", {
            "request_id": payload.request_id,
            "snapshot_id": snapshot.get("snapshot_id", ""),
            "target_url": payload.target_url or ((snapshot.get("analysis_payload") or {}).get("target_url") or ""),
            "source_tool": payload.source_tool or "repeater",
        })
        job = job_manager.submit(payload)
        return AnalysisJobAcceptedResponse(**job)
    except Exception as exc:
        _handle_internal_error(request, "Burp direct job submission failed.", exc)


@app.post("/api/bchecks/recommend", response_model=BCheckRecommendationResponse)
async def recommend_bchecks_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return BCheckRecommendationResponse(**recommend_bchecks_for_exchange(payload))
    except Exception as exc:
        _handle_internal_error(request, "BCheck recommendation failed.", exc)


@app.post("/api/bchecks/results", response_model=BCheckResultIngestResponse)
async def ingest_bcheck_result_endpoint(payload: BCheckResultIngestRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        append_bcheck_result(
            payload,
            selected_bcheck=payload.selected_bcheck,
            outcome_label=payload.outcome_label,
            notes=payload.notes,
            evidence_signal=payload.evidence_signal,
            issue_id=payload.issue_id,
        )
        issue_id = payload.issue_id or ((payload.burp_dashboard_issue or {}).get("issue_id") or "")
        vuln_class = (
            payload.selected_bcheck.get("selected_for_vuln_class")
            or payload.selected_bcheck.get("vuln_class")
            or ((payload.burp_dashboard_issue or {}).get("vuln_hint") or "")
            or "general"
        )
        issue_family_memory = summarize_issue_family_memory(
            payload,
            issue_id=issue_id,
            vuln_classes=[vuln_class],
        )
        next_step = build_one_best_next_step(
            title="Review the updated issue-family memory before importing another BCheck.",
            source="bcheck-result-ingestion",
            why="The bridge now has a fresh signal about whether the last official BCheck helped or stayed noisy on this exact issue family.",
            manual_step="Use /api/bchecks/recommend again and prefer one unsuppressed official BCheck only if the family is still narrow enough.",
            expected_signal="A stronger next recommendation that avoids the just-recorded noisy or low-value check.",
            stop_when="One official check remains useful, or the bridge recommends returning to Repeater/manual proof instead.",
            supporting_references=list(payload.selected_bcheck.get("selection_references") or [])[:6],
        )
        summary = (
            f"Recorded {payload.outcome_label} for "
            f"{payload.selected_bcheck.get('name') or payload.selected_bcheck.get('relative_path') or 'the selected official BCheck'}."
        )
        return BCheckResultIngestResponse(
            recorded=True,
            result_label=payload.outcome_label,
            selected_bcheck=OfficialBCheckSelectionResponse(**payload.selected_bcheck),
            issue_family_memory=issue_family_memory,
            one_best_next_step=OneBestNextStepResponse(**next_step),
            summary=summary,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _handle_internal_error(request, "BCheck result ingestion failed.", exc)


@app.post("/api/project/readiness", response_model=ProjectReadinessResponse)
async def project_readiness_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return ProjectReadinessResponse(**review_project_readiness(payload))
    except Exception as exc:
        _handle_internal_error(request, "Project readiness review failed.", exc)


@app.post("/api/browser/verify-plan", response_model=BrowserVerificationResponse)
async def browser_verify_plan_endpoint(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        effective_payload = payload
        if not BROWSER_VERIFICATION_REQUIRE_EXPLICIT_ALLOW and payload.browser_allowed_workflows and not payload.browser_verification_allowed:
            if hasattr(payload, "model_copy"):
                effective_payload = payload.model_copy(update={"browser_verification_allowed": True})
            else:
                effective_payload = payload.copy(update={"browser_verification_allowed": True})
        result = build_browser_verification_plan(effective_payload)
        return BrowserVerificationResponse(**result)
    except Exception as exc:
        _handle_internal_error(request, "Browser verification planning failed.", exc)


@app.post("/api/analyze/jobs", response_model=AnalysisJobAcceptedResponse)
async def create_analysis_job(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        append_audit_event("job_submit", {
            "request_id": payload.request_id,
            "target_url": payload.target_url,
            "http_method": payload.http_method,
            "batch_id": payload.batch_id,
            "privacy_mode_override": payload.privacy_mode_override,
        })
        job = job_manager.submit(payload)
        return AnalysisJobAcceptedResponse(**job)
    except Exception as exc:
        _handle_internal_error(request, "AI Bridge job submission failed.", exc)


@app.get("/api/analyze/jobs/{job_id}", response_model=AnalysisJobStatusResponse)
async def get_analysis_job(job_id: str):
    job = job_manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")

    result = job.get("result")
    if result is not None:
        job["result"] = AdvisoryResponse(**result)
    analysis_run = job.get("analysis_run")
    if analysis_run is not None:
        job["analysis_run"] = AnalysisRunResponse(**analysis_run)

    return AnalysisJobStatusResponse(**job)


@app.get("/api/history/recent", response_model=List[HistoryRecordResponse])
async def recent_history(limit: int = 20, request_id: str = "", status: str = ""):
    page = paginate_history_records(limit=max(1, min(limit, 200)), cursor=0, request_id=request_id, status=status)
    result = []
    for record in page["items"]:
        entry = dict(record)
        if entry.get("result") is not None:
            entry["result"] = AdvisoryResponse(**entry["result"])
        if entry.get("analysis_run") is not None:
            entry["analysis_run"] = AnalysisRunResponse(**entry["analysis_run"])
        result.append(HistoryRecordResponse(**entry))
    return result


@app.get("/api/history/recent/page", response_model=HistoryRecordPageResponse)
async def recent_history_page(limit: int = 20, cursor: int = 0, request_id: str = "", status: str = ""):
    page = paginate_history_records(limit=limit, cursor=cursor, request_id=request_id, status=status)
    items = []
    for record in page["items"]:
        entry = dict(record)
        if entry.get("result") is not None:
            entry["result"] = AdvisoryResponse(**entry["result"])
        if entry.get("analysis_run") is not None:
            entry["analysis_run"] = AnalysisRunResponse(**entry["analysis_run"])
        items.append(HistoryRecordResponse(**entry))
    page["items"] = items
    return HistoryRecordPageResponse(**page)


@app.get("/api/history/recent/export.md")
async def recent_history_markdown(limit: int = 20, cursor: int = 0, request_id: str = "", status: str = ""):
    page = paginate_history_records(limit=limit, cursor=cursor, request_id=request_id, status=status)
    return Response(content=history_records_markdown(page), media_type="text/markdown; charset=utf-8")


@app.get("/api/history/recent/export.jsonl")
async def recent_history_jsonl(limit: int = 20, cursor: int = 0, request_id: str = "", status: str = ""):
    page = paginate_history_records(limit=limit, cursor=cursor, request_id=request_id, status=status)
    return Response(content=history_records_jsonl(page["items"]), media_type="application/x-ndjson; charset=utf-8")


@app.get("/api/history/jobs/{job_id}", response_model=HistoryRecordResponse)
async def job_history_json(job_id: str):
    record = get_job_record(job_id)
    if not record:
        raise HTTPException(status_code=404, detail="History record not found.")
    entry = dict(record)
    if entry.get("result") is not None:
        entry["result"] = AdvisoryResponse(**entry["result"])
    if entry.get("analysis_run") is not None:
        entry["analysis_run"] = AnalysisRunResponse(**entry["analysis_run"])
    return HistoryRecordResponse(**entry)


@app.get("/api/history/jobs/{job_id}/report.md")
async def job_history_markdown(job_id: str):
    record = get_job_record(job_id)
    if not record:
        raise HTTPException(status_code=404, detail="History record not found.")
    markdown = job_summary_markdown(record)
    return Response(content=markdown, media_type="text/markdown; charset=utf-8")


@app.get("/api/history/jobs/{job_id}/evidence", response_model=ReportEvidenceResponse)
async def job_history_evidence(job_id: str):
    try:
        return ReportEvidenceResponse(**build_report_evidence(job_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="History record not found.")


@app.get("/api/history/jobs/{job_id}/report", response_model=StructuredReportResponse)
async def job_history_report(job_id: str, snapshot_id: str = ""):
    try:
        return StructuredReportResponse(**build_structured_report_for_job(job_id, snapshot_id=snapshot_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="History record not found.")


@app.get("/api/history/jobs/{job_id}/submission-report", response_model=BugBountySubmissionResponse)
async def job_history_submission_report(job_id: str, platform: str = "", snapshot_id: str = ""):
    try:
        return BugBountySubmissionResponse(**build_bug_bounty_submission(job_id, platform=platform, snapshot_id=snapshot_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="History record not found.")


@app.get("/api/history/jobs/{job_id}/operator-review", response_model=OperatorReviewResponse)
async def job_history_operator_review(job_id: str, platform: str = "", snapshot_id: str = ""):
    try:
        return OperatorReviewResponse(**build_operator_review(job_id, platform=platform, snapshot_id=snapshot_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="History record not found.")


@app.get("/api/history/jobs/{job_id}/submission-report.md")
async def job_history_submission_report_markdown(job_id: str, platform: str = "", snapshot_id: str = ""):
    try:
        report = build_bug_bounty_submission(job_id, platform=platform, snapshot_id=snapshot_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="History record not found.")
    return Response(content=report.get("markdown", ""), media_type="text/markdown; charset=utf-8")


@app.get("/api/history/jobs/{job_id}/evidence-bundle", response_model=EvidenceBundleResponse)
async def job_history_evidence_bundle(job_id: str, platform: str = "", snapshot_id: str = ""):
    try:
        return EvidenceBundleResponse(**build_evidence_bundle(job_id, platform=platform, snapshot_id=snapshot_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="History record not found.")


@app.get("/api/history/jobs/{job_id}/evidence-bundle.md")
async def job_history_evidence_bundle_markdown(job_id: str, platform: str = "", snapshot_id: str = ""):
    try:
        bundle = build_evidence_bundle(job_id, platform=platform, snapshot_id=snapshot_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="History record not found.")
    return Response(content=render_evidence_bundle_markdown(bundle), media_type="text/markdown; charset=utf-8")


@app.get("/api/history/snapshots/{snapshot_id}", response_model=BurpSessionSnapshotResponse)
async def history_snapshot(snapshot_id: str):
    snapshot = get_burp_session_snapshot(snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Burp session snapshot not found.")
    return BurpSessionSnapshotResponse(**snapshot)


@app.get("/api/history/jobs/{job_id}/phases", response_model=PhaseHistoryResponse)
async def job_phase_history(job_id: str, phase: str = "", limit: int = 20):
    try:
        return PhaseHistoryResponse(**query_phase_history(job_id=job_id, phase=phase, limit=limit))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/history/jobs/{job_id}/reasoning", response_model=AnalysisReasoningResponse)
async def job_reasoning(job_id: str):
    try:
        return AnalysisReasoningResponse(**explain_analysis_run(job_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/history/similar", response_model=SimilarHistoryResponse)
async def similar_history(payload: AssessmentRequest, limit: int = 5):
    result = query_similar_history(payload, limit=limit)
    return SimilarHistoryResponse(**result)


@app.get("/api/history/batches/{batch_id}")
async def batch_history_json(batch_id: str):
    records = get_batch_records(batch_id)
    if not records:
        raise HTTPException(status_code=404, detail="Batch history not found.")
    return summarize_batch(records)


@app.get("/api/history/batches/{batch_id}/export.md")
async def batch_history_markdown(batch_id: str):
    records = get_batch_records(batch_id)
    if not records:
        raise HTTPException(status_code=404, detail="Batch history not found.")
    markdown = batch_summary_markdown(summarize_batch(records))
    return Response(content=markdown, media_type="text/markdown; charset=utf-8")


@app.post("/api/history/feedback", response_model=FeedbackResponse)
async def record_history_feedback(payload: FeedbackRequest):
    normalized_label = (payload.label or "").strip().lower()
    if normalized_label not in FEEDBACK_WEIGHTS:
        allowed = ", ".join(sorted(FEEDBACK_WEIGHTS.keys()))
        raise HTTPException(status_code=400, detail=f"Unsupported feedback label. Use one of: {allowed}")

    matching_record = next((record for record in read_history_records() if record.get("job_id") == payload.job_id), None)
    if not matching_record:
        raise HTTPException(status_code=404, detail="History record not found for the supplied job_id.")

    append_feedback_record(payload.job_id, normalized_label, payload.notes or "")
    related_feedback = [
        entry for entry in read_feedback_records()
        if entry.get("job_id") == payload.job_id
    ]

    latest_entry = related_feedback[-1]
    return FeedbackResponse(
        job_id=payload.job_id,
        label=normalized_label,
        notes=latest_entry.get("notes", ""),
        recorded_at=latest_entry.get("created_at", ""),
        related_feedback_count=len(related_feedback),
    )


@app.post("/api/kb/guidance-feedback", response_model=GuidanceFeedbackResponse)
async def record_guidance_feedback(payload: GuidanceFeedbackRequest):
    normalized_label = (payload.label or "").strip().lower()
    if normalized_label not in FEEDBACK_WEIGHTS:
        allowed = ", ".join(sorted(FEEDBACK_WEIGHTS.keys()))
        raise HTTPException(status_code=400, detail=f"Unsupported feedback label. Use one of: {allowed}")
    if not payload.guidance_pack_ids:
        raise HTTPException(status_code=400, detail="guidance_pack_ids must include at least one pack id.")
    result = append_guidance_feedback(
        payload.job_id,
        normalized_label,
        payload.guidance_pack_ids,
        payload.notes or "",
    )
    return GuidanceFeedbackResponse(**result)


@app.post("/api/burp/assets/feedback", response_model=BurpAssetFeedbackResponse)
async def record_burp_asset_feedback(payload: BurpAssetFeedbackRequest):
    normalized_label = (payload.label or "").strip().lower().replace(" ", "_")
    if normalized_label not in ASSET_FEEDBACK_WEIGHTS and normalized_label not in {"high-signal", "high_signal", "false-positive", "not-useful"}:
        allowed = ", ".join(sorted(ASSET_FEEDBACK_WEIGHTS.keys()))
        raise HTTPException(status_code=400, detail=f"Unsupported asset feedback label. Use one of: {allowed}")
    try:
        result = append_asset_feedback(
            asset_type=payload.asset_type,
            asset_id=payload.asset_id,
            label=payload.label,
            target_url=payload.target_url,
            vuln_class=payload.vuln_class,
            selected_profile=payload.selected_profile,
            program_platform=payload.program_platform,
            program_policy_template=payload.program_policy_template,
            notes=payload.notes,
            job_id=payload.job_id,
            request_id=payload.request_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return BurpAssetFeedbackResponse(**result)


@app.post("/api/history/hypotheses/status", response_model=HypothesisStatusResponse)
async def set_hypothesis_status(payload: HypothesisStatusRequest):
    try:
        result = update_hypothesis_status(
            payload.job_id,
            payload.hypothesis_id,
            payload.status,
            payload.notes or "",
        )
        return HypothesisStatusResponse(**result)
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail.lower():
            raise HTTPException(status_code=404, detail=detail)
        raise HTTPException(status_code=400, detail=detail)


@app.get("/api/kb/status", response_model=KnowledgeStatusResponse)
async def kb_status():
    kb_dir = Path(KB_DIR)
    rag_dir = Path(RAG_DIR)
    return KnowledgeStatusResponse(
        kb_dir=str(kb_dir),
        rag_dir=str(rag_dir),
        documents=len(list(kb_dir.glob("*.md"))) if kb_dir.exists() else 0,
        index_present=(rag_dir / "kb_index.json").exists(),
    )


@app.get("/api/kb/guidance-db", response_model=GuidanceDbResponse)
async def guidance_db(vuln_class: str = "", style: str = "", limit: int = 6):
    vuln_classes = [item.strip() for item in vuln_class.split(",") if item.strip()] or ["general"]
    styles = [item.strip() for item in style.split(",") if item.strip()]
    result = query_guidance_packs(vuln_classes, styles=styles, top_k=max(1, min(limit, 12)))
    return GuidanceDbResponse(**result)


@app.get("/api/runtime/health", response_model=RuntimeHealthResponse)
async def runtime_health():
    return RuntimeHealthResponse(**get_runtime_health())


@app.get("/api/runtime/model-options", response_model=RuntimeModelOptionsResponse)
async def runtime_model_options():
    return RuntimeModelOptionsResponse(**get_runtime_model_options())


@app.post("/api/runtime/model-selection", response_model=RuntimeModelOptionsResponse)
async def runtime_model_selection(payload: RuntimeModelSelectionRequest, request: Request):
    try:
        actor = payload.actor or _request_id(request)
        result = select_runtime_model(payload.model_name, source=payload.source, actor=actor)
        append_audit_event(
            "runtime_model_switch",
            {
                "request_id": _request_id(request),
                "actor": actor,
                "source": payload.source,
                "active_model": result.get("current_model") or "",
            },
        )
        return RuntimeModelOptionsResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/runtime/model-selection", response_model=RuntimeModelOptionsResponse)
async def runtime_model_selection_reset(request: Request):
    result = clear_runtime_model_selection()
    append_audit_event(
        "runtime_model_reset",
        {
            "request_id": _request_id(request),
            "active_model": result.get("current_model") or "",
        },
    )
    return RuntimeModelOptionsResponse(**result)


@app.post("/api/runtime/readiness", response_model=RuntimeReadinessResponse)
async def runtime_readiness(payload: AssessmentRequest, request: Request):
    payload = _payload_with_request_id(payload, request)
    try:
        return RuntimeReadinessResponse(**get_runtime_readiness(payload))
    except Exception as exc:
        _handle_internal_error(request, "Runtime readiness assessment failed.", exc)


@app.get("/api/runtime/provider-diagnostics", response_model=ProviderDiagnosticsHistoryResponse)
async def runtime_provider_diagnostics(
    limit: int = 20,
    cursor: int = 0,
    job_id: str = "",
    request_id: str = "",
    provider: str = "",
    final_status: str = "",
):
    return ProviderDiagnosticsHistoryResponse(
        **get_provider_diagnostics_history(
            limit=limit,
            cursor=cursor,
            job_id=job_id,
            request_id=request_id,
            provider=provider,
            final_status=final_status,
        )
    )


@app.get("/api/runtime/provider-diagnostics/export.md")
async def runtime_provider_diagnostics_markdown(
    limit: int = 20,
    cursor: int = 0,
    job_id: str = "",
    request_id: str = "",
    provider: str = "",
    final_status: str = "",
):
    page = get_provider_diagnostics_history(
        limit=limit,
        cursor=cursor,
        job_id=job_id,
        request_id=request_id,
        provider=provider,
        final_status=final_status,
    )
    return Response(content=provider_diagnostics_markdown(page), media_type="text/markdown; charset=utf-8")


@app.get("/api/runtime/provider-diagnostics/export.jsonl")
async def runtime_provider_diagnostics_jsonl(
    limit: int = 20,
    cursor: int = 0,
    job_id: str = "",
    request_id: str = "",
    provider: str = "",
    final_status: str = "",
):
    page = get_provider_diagnostics_history(
        limit=limit,
        cursor=cursor,
        job_id=job_id,
        request_id=request_id,
        provider=provider,
        final_status=final_status,
    )
    return Response(content=provider_diagnostics_jsonl(page["items"]), media_type="application/x-ndjson; charset=utf-8")


@app.get("/api/runtime/benchmark", response_model=RuntimeBenchmarkResponse)
async def runtime_benchmark(limit: int = 100):
    return RuntimeBenchmarkResponse(**build_runtime_benchmark(limit=limit))


@app.get("/api/audit/events", response_model=AuditEventPageResponse)
async def audit_events(limit: int = 20, cursor: int = 0, request_id: str = "", job_id: str = "", event_type: str = ""):
    page = paginate_audit_events(limit=limit, cursor=cursor, request_id=request_id, job_id=job_id, event_type=event_type)
    return AuditEventPageResponse(**page)


@app.get("/api/audit/events/export.md")
async def audit_events_markdown_export(limit: int = 20, cursor: int = 0, request_id: str = "", job_id: str = "", event_type: str = ""):
    page = paginate_audit_events(limit=limit, cursor=cursor, request_id=request_id, job_id=job_id, event_type=event_type)
    return Response(content=audit_events_markdown(page), media_type="text/markdown; charset=utf-8")


@app.get("/api/audit/events/export.jsonl")
async def audit_events_jsonl_export(limit: int = 20, cursor: int = 0, request_id: str = "", job_id: str = "", event_type: str = ""):
    page = paginate_audit_events(limit=limit, cursor=cursor, request_id=request_id, job_id=job_id, event_type=event_type)
    return Response(content=audit_events_jsonl(page["items"]), media_type="application/x-ndjson; charset=utf-8")


@app.get("/api/profiles", response_model=List[ProfileResponse])
async def profiles():
    return [ProfileResponse(**profile) for profile in list_runtime_profiles()]


@app.get("/api/policies/templates", response_model=List[ProgramPolicyTemplateResponse])
async def program_policy_templates():
    return [ProgramPolicyTemplateResponse(**template) for template in list_program_policy_templates()]


@app.get("/api/policies/templates/{template_name}", response_model=ProgramPolicyTemplateResponse)
async def program_policy_template(template_name: str):
    template = get_program_policy_template(template_name or DEFAULT_BOUNTY_PLATFORM)
    return ProgramPolicyTemplateResponse(**template)


@app.get("/api/submissions/regressions", response_model=SubmissionRegressionResponse)
async def submission_regressions(vuln_class: str = "", outcome: str = "", platform: str = "", limit: int = 10):
    return SubmissionRegressionResponse(
        **query_submission_regressions(
            vuln_class=vuln_class,
            outcome=outcome,
            platform=platform,
            limit=limit,
        )
    )


@app.post("/api/submissions/regressions/import", response_model=SubmissionRegressionImportResponse)
async def import_submission_regressions(payload: SubmissionRegressionImportRequest):
    result = import_submission_regressions_into_review_dataset(
        vuln_class=payload.vuln_class,
        outcome=payload.outcome,
        platform=payload.platform,
        limit=payload.limit,
    )
    return SubmissionRegressionImportResponse(**result)


@app.get("/api/submissions/wording-comparisons", response_model=WordingComparisonResponse)
async def submission_wording_comparisons(vuln_class: str, platform: str = ""):
    return WordingComparisonResponse(**build_wording_comparison(vuln_class, platform=platform))


@app.get("/api/bchecks/status", response_model=BCheckStatusResponse)
async def bchecks_status():
    return BCheckStatusResponse(**get_bcheck_status())


@app.get("/api/bchecks/catalog", response_model=List[BCheckCatalogEntryResponse])
async def bchecks_catalog(limit: int = 100, vuln_class: str = "", search: str = ""):
    entries = query_bchecks(limit=max(1, min(limit, 500)), vuln_class=vuln_class, search=search)
    return [BCheckCatalogEntryResponse(**entry) for entry in entries]


@app.get("/api/bchecks/content", response_model=BCheckContentResponse)
async def bcheck_content(relative_path: str):
    normalized = (relative_path or "").strip().replace("\\", "/")
    if not normalized or ".." in normalized:
        raise HTTPException(status_code=400, detail="A valid relative_path is required.")

    candidate = (REPO_DIR / normalized).resolve()
    repo_root = REPO_DIR.resolve()
    if not str(candidate).startswith(str(repo_root)) or not candidate.exists() or candidate.suffix.lower() != ".bcheck":
        raise HTTPException(status_code=404, detail="Requested BCheck file was not found.")

    return BCheckContentResponse(
        relative_path=normalized,
        name=candidate.stem,
        content=candidate.read_text(encoding="utf-8", errors="replace"),
    )


@app.post("/api/bchecks/sync", response_model=BCheckSyncResponse)
async def bchecks_sync(request: Request):
    try:
        status = sync_bchecks_repository()
        return BCheckSyncResponse(**status, synced=True, detail="BChecks repository synced successfully.")
    except Exception as exception:
        logger.error("BChecks sync failed [request_id=%s]: %s\n%s", _request_id(request), exception, traceback.format_exc())
        status = get_bcheck_status()
        return BCheckSyncResponse(**status, synced=False, detail=str(exception))


@app.get("/api/tools/inventory", response_model=KaliToolInventoryResponse)
async def tools_inventory(refresh: bool = False):
    return KaliToolInventoryResponse(**get_tool_inventory(force_refresh=refresh))


@app.post("/api/kb/note")
async def add_kb_note(payload: KnowledgeNoteRequest, request: Request):
    try:
        note_path = write_note(payload.title, payload.content, payload.source or "", payload.tags or [])
        index_info = rebuild_index()
        return {
            "saved_note": str(note_path),
            "index": index_info,
        }
    except Exception as exc:
        _handle_internal_error(request, "KB note write failed.", exc)


@app.post("/api/kb/reindex")
async def reindex_kb(request: Request):
    try:
        return rebuild_index()
    except Exception as exc:
        _handle_internal_error(request, "KB reindex failed.", exc)
