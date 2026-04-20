from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class Hypothesis:
    id: str
    vuln_class: str
    summary: str
    confidence: float
    status: str = "suspected"
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    impact_paths: list[str] = field(default_factory=list)
    next_checks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class EvidenceItem:
    source: str
    summary: str
    evidence_type: str = ""
    confidence: float = 0.5
    request_ref: str = ""
    response_ref: str = ""
    delta: str = ""
    notes: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class AnalysisRun:
    phases: dict
    request_id: str = ""
    input_context: dict = field(default_factory=dict)
    phase_results: dict = field(default_factory=dict)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    provider_trace: list[str] = field(default_factory=list)
    final_recommendation: str = ""
    fallback_reason: str = ""

    def to_dict(self) -> dict:
        phase_results = self.phase_results or self.phases
        return {
            "request_id": self.request_id,
            "input_context": dict(self.input_context),
            "phase_results": phase_results,
            "phases": self.phases,
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "evidence": [item.to_dict() for item in self.evidence],
            "provider_trace": list(self.provider_trace),
            "final_recommendation": self.final_recommendation,
            "fallback_reason": self.fallback_reason,
        }
