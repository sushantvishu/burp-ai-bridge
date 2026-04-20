package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class KaliToolInfo {
    @JsonProperty("name")
    private String name;

    @JsonProperty("binary")
    private String binary;

    @JsonProperty("repo_url")
    private String repoUrl;

    @JsonProperty("summary")
    private String summary;

    @JsonProperty("install_hint")
    private String installHint;

    @JsonProperty("installed")
    private boolean installed;

    @JsonProperty("command_path")
    private String commandPath;

    @JsonProperty("version")
    private String version;

    @JsonProperty("help_preview")
    private String helpPreview;

    public KaliToolInfo() {
    }

    public String getName() {
        return name == null ? "" : name;
    }

    public String getBinary() {
        return binary == null ? "" : binary;
    }

    public String getRepoUrl() {
        return repoUrl == null ? "" : repoUrl;
    }

    public String getSummary() {
        return summary == null ? "" : summary;
    }

    public String getInstallHint() {
        return installHint == null ? "" : installHint;
    }

    public boolean isInstalled() {
        return installed;
    }

    public String getCommandPath() {
        return commandPath == null ? "" : commandPath;
    }

    public String getVersion() {
        return version == null ? "" : version;
    }

    public String getHelpPreview() {
        return helpPreview == null ? "" : helpPreview;
    }
}
