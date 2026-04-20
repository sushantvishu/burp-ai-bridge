package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class AnalysisReasoningEvidenceResponse {
    @JsonProperty("source")
    private String source;

    @JsonProperty("evidence_type")
    private String evidenceType;

    @JsonProperty("summary")
    private String summary;

    @JsonProperty("confidence")
    private double confidence;

    public String getSource() {
        return source == null ? "" : source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getEvidenceType() {
        return evidenceType == null ? "" : evidenceType;
    }

    public void setEvidenceType(String evidenceType) {
        this.evidenceType = evidenceType;
    }

    public String getSummary() {
        return summary == null ? "" : summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }
}
