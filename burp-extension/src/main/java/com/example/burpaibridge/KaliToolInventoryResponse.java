package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class KaliToolInventoryResponse {
    @JsonProperty("available")
    private boolean available;

    @JsonProperty("distro")
    private String distro;

    @JsonProperty("distro_name")
    private String distroName;

    @JsonProperty("detected_at")
    private String detectedAt;

    @JsonProperty("installed_count")
    private int installedCount;

    @JsonProperty("missing_count")
    private int missingCount;

    @JsonProperty("tool_help_text")
    private String toolHelpText;

    @JsonProperty("error")
    private String error;

    @JsonProperty("tools")
    private List<KaliToolInfo> tools = new ArrayList<>();

    public KaliToolInventoryResponse() {
    }

    public boolean isAvailable() {
        return available;
    }

    public String getDistro() {
        return distro == null ? "" : distro;
    }

    public String getDistroName() {
        return distroName == null ? "" : distroName;
    }

    public String getDetectedAt() {
        return detectedAt == null ? "" : detectedAt;
    }

    public int getInstalledCount() {
        return installedCount;
    }

    public int getMissingCount() {
        return missingCount;
    }

    public String getToolHelpText() {
        return toolHelpText == null ? "" : toolHelpText;
    }

    public String getError() {
        return error == null ? "" : error;
    }

    public List<KaliToolInfo> getTools() {
        return tools == null ? List.of() : List.copyOf(tools);
    }
}
