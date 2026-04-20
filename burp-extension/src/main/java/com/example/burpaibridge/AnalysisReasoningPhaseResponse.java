package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class AnalysisReasoningPhaseResponse {
    @JsonProperty("phase")
    private String phase;

    @JsonProperty("summary")
    private String summary;

    public String getPhase() {
        return phase == null ? "" : phase;
    }

    public void setPhase(String phase) {
        this.phase = phase;
    }

    public String getSummary() {
        return summary == null ? "" : summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }
}
