package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class BCheckContentResponse {
    @JsonProperty("relative_path")
    private String relativePath;

    @JsonProperty("name")
    private String name;

    @JsonProperty("content")
    private String content;

    public BCheckContentResponse() {
    }

    public String getRelativePath() {
        return relativePath == null ? "" : relativePath;
    }

    public String getName() {
        return name == null ? "" : name;
    }

    public String getContent() {
        return content == null ? "" : content;
    }
}
