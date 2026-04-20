package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class PhaseHistoryResponse {
    @JsonProperty("job_id")
    private String jobId;

    @JsonProperty("phase")
    private String phase;

    @JsonProperty("count")
    private int count;

    @JsonProperty("items")
    private List<PhaseSnapshotResponse> items = new ArrayList<>();

    public String getJobId() {
        return jobId == null ? "" : jobId;
    }

    public void setJobId(String jobId) {
        this.jobId = jobId;
    }

    public String getPhase() {
        return phase == null ? "" : phase;
    }

    public void setPhase(String phase) {
        this.phase = phase;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public List<PhaseSnapshotResponse> getItems() {
        return items == null ? List.of() : List.copyOf(items);
    }

    public void setItems(List<PhaseSnapshotResponse> items) {
        this.items = items == null ? new ArrayList<>() : new ArrayList<>(items);
    }
}
