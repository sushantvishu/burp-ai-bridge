package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class BCheckCatalogEntry {
    @JsonProperty("name")
    private String name;

    @JsonProperty("description")
    private String description;

    @JsonProperty("author")
    private String author;

    @JsonProperty("relative_path")
    private String relativePath;

    @JsonProperty("scan_mode")
    private String scanMode;

    @JsonProperty("execution_context")
    private String executionContext;

    @JsonProperty("tags")
    private List<String> tags = new ArrayList<>();

    @JsonProperty("vuln_classes")
    private List<String> vulnClasses = new ArrayList<>();

    @JsonProperty("usage_hint")
    private String usageHint;

    public BCheckCatalogEntry() {
    }

    public String displayLabel() {
        return firstNonBlank(name, "Unnamed BCheck")
                + " | " + firstNonBlank(relativePath, "no-path")
                + " | " + firstNonBlank(scanMode, "mode-unknown");
    }

    public String selectionLabel() {
        return firstNonBlank(name, "Unnamed BCheck")
                + " | " + firstNonBlank(relativePath, "no-path")
                + " | " + firstNonBlank(scanMode, "mode-unknown");
    }

    public String tooltipText() {
        StringBuilder builder = new StringBuilder();
        builder.append(firstNonBlank(name, "Unnamed BCheck"));
        if (!firstNonBlank(description, "").isBlank()) {
            builder.append(System.lineSeparator()).append(description);
        }
        if (!firstNonBlank(usageHint, "").isBlank()) {
            builder.append(System.lineSeparator()).append("Hint: ").append(usageHint);
        }
        if (!firstNonBlank(author, "").isBlank()) {
            builder.append(System.lineSeparator()).append("Author: ").append(author);
        }
        if (!tags.isEmpty()) {
            builder.append(System.lineSeparator()).append("Tags: ").append(String.join(", ", tags));
        }
        if (!vulnClasses.isEmpty()) {
            builder.append(System.lineSeparator()).append("Classes: ").append(String.join(", ", vulnClasses));
        }
        if (!firstNonBlank(executionContext, "").isBlank()) {
            builder.append(System.lineSeparator()).append("Context: ").append(executionContext);
        }
        return builder.toString();
    }

    public boolean matchesFilter(String filter) {
        String haystack = String.join(
                " ",
                firstNonBlank(name, ""),
                firstNonBlank(description, ""),
                firstNonBlank(relativePath, ""),
                firstNonBlank(scanMode, ""),
                firstNonBlank(executionContext, ""),
                firstNonBlank(usageHint, ""),
                String.join(" ", tags),
                String.join(" ", vulnClasses)
        ).toLowerCase();
        return haystack.contains(filter == null ? "" : filter.toLowerCase());
    }

    public boolean matchesRecommended(List<String> recommendations) {
        if (recommendations == null || recommendations.isEmpty()) {
            return false;
        }
        String path = firstNonBlank(relativePath, "").toLowerCase();
        String title = firstNonBlank(name, "").toLowerCase();
        for (String recommendation : recommendations) {
            String value = firstNonBlank(recommendation, "").toLowerCase();
            if (!path.isBlank() && value.contains(path)) {
                return true;
            }
            if (!title.isBlank() && value.contains(title)) {
                return true;
            }
        }
        return false;
    }

    public boolean matchesPotentialFindings(List<String> findings) {
        if (findings == null || findings.isEmpty()) {
            return false;
        }
        String haystack = String.join(
                " ",
                firstNonBlank(name, ""),
                firstNonBlank(description, ""),
                firstNonBlank(relativePath, ""),
                String.join(" ", tags),
                String.join(" ", vulnClasses)
        ).toLowerCase();
        for (String finding : findings) {
            String normalized = firstNonBlank(finding, "").toLowerCase();
            for (String token : normalized.split("[^a-z0-9]+")) {
                if (token.length() >= 4 && haystack.contains(token)) {
                    return true;
                }
            }
        }
        return false;
    }

    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
