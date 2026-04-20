package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class AnalysisReasoningResponse {
    @JsonProperty("job_id")
    private String jobId;

    @JsonProperty("target_url")
    private String targetUrl;

    @JsonProperty("top_hypothesis")
    private Map<String, Object> topHypothesis = new LinkedHashMap<>();

    @JsonProperty("phase_highlights")
    private List<AnalysisReasoningPhaseResponse> phaseHighlights = new ArrayList<>();

    @JsonProperty("key_evidence")
    private List<AnalysisReasoningEvidenceResponse> keyEvidence = new ArrayList<>();

    @JsonProperty("confidence_drivers")
    private List<String> confidenceDrivers = new ArrayList<>();

    @JsonProperty("downgrade_reasons")
    private List<String> downgradeReasons = new ArrayList<>();

    @JsonProperty("next_decision")
    private Map<String, Object> nextDecision = new LinkedHashMap<>();

    public String getJobId() {
        return jobId == null ? "" : jobId;
    }

    public void setJobId(String jobId) {
        this.jobId = jobId;
    }

    public String getTargetUrl() {
        return targetUrl == null ? "" : targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public Map<String, Object> getTopHypothesis() {
        return topHypothesis == null ? Map.of() : Map.copyOf(topHypothesis);
    }

    public void setTopHypothesis(Map<String, Object> topHypothesis) {
        this.topHypothesis = topHypothesis == null ? new LinkedHashMap<>() : new LinkedHashMap<>(topHypothesis);
    }

    public List<AnalysisReasoningPhaseResponse> getPhaseHighlights() {
        return phaseHighlights == null ? List.of() : List.copyOf(phaseHighlights);
    }

    public void setPhaseHighlights(List<AnalysisReasoningPhaseResponse> phaseHighlights) {
        this.phaseHighlights = phaseHighlights == null ? new ArrayList<>() : new ArrayList<>(phaseHighlights);
    }

    public List<AnalysisReasoningEvidenceResponse> getKeyEvidence() {
        return keyEvidence == null ? List.of() : List.copyOf(keyEvidence);
    }

    public void setKeyEvidence(List<AnalysisReasoningEvidenceResponse> keyEvidence) {
        this.keyEvidence = keyEvidence == null ? new ArrayList<>() : new ArrayList<>(keyEvidence);
    }

    public List<String> getConfidenceDrivers() {
        return confidenceDrivers == null ? List.of() : List.copyOf(confidenceDrivers);
    }

    public void setConfidenceDrivers(List<String> confidenceDrivers) {
        this.confidenceDrivers = confidenceDrivers == null ? new ArrayList<>() : new ArrayList<>(confidenceDrivers);
    }

    public List<String> getDowngradeReasons() {
        return downgradeReasons == null ? List.of() : List.copyOf(downgradeReasons);
    }

    public void setDowngradeReasons(List<String> downgradeReasons) {
        this.downgradeReasons = downgradeReasons == null ? new ArrayList<>() : new ArrayList<>(downgradeReasons);
    }

    public Map<String, Object> getNextDecision() {
        return nextDecision == null ? Map.of() : Map.copyOf(nextDecision);
    }

    public void setNextDecision(Map<String, Object> nextDecision) {
        this.nextDecision = nextDecision == null ? new LinkedHashMap<>() : new LinkedHashMap<>(nextDecision);
    }
}
