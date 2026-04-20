package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.LinkedHashMap;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class PhaseSnapshotResponse {
    @JsonProperty("job_id")
    private String jobId;

    @JsonProperty("created_at")
    private String createdAt;

    @JsonProperty("target_url")
    private String targetUrl;

    @JsonProperty("phase")
    private String phase;

    @JsonProperty("result")
    private Map<String, Object> result = new LinkedHashMap<>();

    @JsonProperty("input_context")
    private Map<String, Object> inputContext = new LinkedHashMap<>();

    public String getJobId() {
        return jobId == null ? "" : jobId;
    }

    public void setJobId(String jobId) {
        this.jobId = jobId;
    }

    public String getCreatedAt() {
        return createdAt == null ? "" : createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getTargetUrl() {
        return targetUrl == null ? "" : targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getPhase() {
        return phase == null ? "" : phase;
    }

    public void setPhase(String phase) {
        this.phase = phase;
    }

    public Map<String, Object> getResult() {
        return result == null ? Map.of() : Map.copyOf(result);
    }

    public void setResult(Map<String, Object> result) {
        this.result = result == null ? new LinkedHashMap<>() : new LinkedHashMap<>(result);
    }

    public Map<String, Object> getInputContext() {
        return inputContext == null ? Map.of() : Map.copyOf(inputContext);
    }

    public void setInputContext(Map<String, Object> inputContext) {
        this.inputContext = inputContext == null ? new LinkedHashMap<>() : new LinkedHashMap<>(inputContext);
    }
}
