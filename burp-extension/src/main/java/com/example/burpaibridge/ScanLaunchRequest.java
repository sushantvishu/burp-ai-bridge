package com.example.burpaibridge;

import java.util.ArrayList;
import java.util.List;

public final class ScanLaunchRequest {
    private final String targetUrl;
    private final String scanType;
    private final String auditConfiguration;
    private final List<String> selectedBchecks;

    public ScanLaunchRequest(String targetUrl, String scanType, String auditConfiguration, List<String> selectedBchecks) {
        this.targetUrl = targetUrl == null ? "" : targetUrl.trim();
        this.scanType = scanType == null ? "" : scanType.trim();
        this.auditConfiguration = auditConfiguration == null ? "" : auditConfiguration.trim();
        this.selectedBchecks = selectedBchecks == null ? new ArrayList<>() : new ArrayList<>(selectedBchecks);
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public String getScanType() {
        return scanType;
    }

    public String getAuditConfiguration() {
        return auditConfiguration;
    }

    public List<String> getSelectedBchecks() {
        return List.copyOf(selectedBchecks);
    }
}
