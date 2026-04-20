package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.LinkedHashMap;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class PreparedBurpExportResponse {
    @JsonProperty("contract_version")
    private String contractVersion;

    @JsonProperty("payload")
    private Map<String, Object> payload = new LinkedHashMap<>();

    @JsonProperty("summary")
    private Map<String, Object> summary = new LinkedHashMap<>();

    @JsonProperty("next_step")
    private Map<String, Object> nextStep = new LinkedHashMap<>();

    public String getContractVersion() {
        return contractVersion == null ? "" : contractVersion;
    }

    public void setContractVersion(String contractVersion) {
        this.contractVersion = contractVersion;
    }

    public Map<String, Object> getPayload() {
        return payload == null ? Map.of() : Map.copyOf(payload);
    }

    public void setPayload(Map<String, Object> payload) {
        this.payload = payload == null ? new LinkedHashMap<>() : new LinkedHashMap<>(payload);
    }

    public Map<String, Object> getSummary() {
        return summary == null ? Map.of() : Map.copyOf(summary);
    }

    public void setSummary(Map<String, Object> summary) {
        this.summary = summary == null ? new LinkedHashMap<>() : new LinkedHashMap<>(summary);
    }

    public Map<String, Object> getNextStep() {
        return nextStep == null ? Map.of() : Map.copyOf(nextStep);
    }

    public void setNextStep(Map<String, Object> nextStep) {
        this.nextStep = nextStep == null ? new LinkedHashMap<>() : new LinkedHashMap<>(nextStep);
    }
}
