package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class AnalysisJobAccepted {
    @JsonProperty("job_id")
    private String jobId;

    @JsonProperty("status")
    private String status;

    @JsonProperty("status_message")
    private String statusMessage;

    @JsonProperty("estimated_duration")
    private String estimatedDuration;

    @JsonProperty("complexity")
    private String complexity;

    @JsonProperty("recommendation")
    private String recommendation;

    public AnalysisJobAccepted() {
    }

    public String getJobId() {
        return jobId == null ? "" : jobId;
    }

    public void setJobId(String jobId) {
        this.jobId = jobId;
    }

    public String getStatus() {
        return status == null ? "queued" : status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getStatusMessage() {
        return statusMessage == null ? "Analysis job accepted." : statusMessage;
    }

    public void setStatusMessage(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public String getEstimatedDuration() {
        return estimatedDuration == null ? "unknown" : estimatedDuration;
    }

    public void setEstimatedDuration(String estimatedDuration) {
        this.estimatedDuration = estimatedDuration;
    }

    public String getComplexity() {
        return complexity == null ? "unknown" : complexity;
    }

    public void setComplexity(String complexity) {
        this.complexity = complexity;
    }

    public String getRecommendation() {
        return recommendation == null ? "" : recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }
}
