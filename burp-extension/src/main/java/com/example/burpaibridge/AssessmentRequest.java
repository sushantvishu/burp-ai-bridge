package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public final class AssessmentRequest {
    @JsonProperty("raw_request")
    private String rawRequest;

    @JsonProperty("raw_response")
    private String rawResponse;

    @JsonProperty("target_url")
    private String targetUrl;

    @JsonProperty("http_method")
    private String httpMethod;

    @JsonProperty("source_tool")
    private String sourceTool;

    @JsonProperty("use_burp_mcp_context")
    private boolean useBurpMcpContext;

    @JsonProperty("annotations")
    private List<String> annotations = new ArrayList<>();

    @JsonProperty("batch_id")
    private String batchId;

    @JsonProperty("batch_index")
    private Integer batchIndex;

    @JsonProperty("batch_total")
    private Integer batchTotal;

    @JsonProperty("operator_answers")
    private Map<String, String> operatorAnswers = new LinkedHashMap<>();

    @JsonProperty("tool_help_text")
    private String toolHelpText;

    @JsonProperty("scope_includes_text")
    private String scopeIncludesText;

    @JsonProperty("scope_excludes_text")
    private String scopeExcludesText;

    @JsonProperty("rate_limit_text")
    private String rateLimitText;

    @JsonProperty("max_concurrency_text")
    private String maxConcurrencyText;

    @JsonProperty("custom_headers_text")
    private String customHeadersText;

    @JsonProperty("program_policy_text")
    private String programPolicyText;

    @JsonProperty("tool_results_text")
    private String toolResultsText;

    @JsonProperty("burp_config_export_text")
    private String burpConfigExportText;

    @JsonProperty("burp_screenshot_audit_text")
    private String burpScreenshotAuditText;

    @JsonProperty("loaded_burp_tools_text")
    private String loadedBurpToolsText;

    @JsonProperty("saved_program_policy_text")
    private String savedProgramPolicyText;

    @JsonProperty("program_screenshot_audit_text")
    private String programScreenshotAuditText;

    @JsonProperty("response_delta_text")
    private String responseDeltaText;

    @JsonProperty("evidence_timeline_entries")
    private List<String> evidenceTimelineEntries = new ArrayList<>();

    @JsonProperty("issue_workflow_notes")
    private List<String> issueWorkflowNotes = new ArrayList<>();

    @JsonProperty("investigation_notebook_text")
    private String investigationNotebookText;

    @JsonProperty("bapp_findings_text")
    private String bappFindingsText;

    @JsonProperty("logger_evidence_text")
    private String loggerEvidenceText;

    @JsonProperty("collaborator_evidence_text")
    private String collaboratorEvidenceText;

    @JsonProperty("privacy_mode_override")
    private String privacyModeOverride;

    @JsonProperty("selected_profile")
    private String selectedProfile;

    @JsonProperty("review_scope_include_classes")
    private List<String> reviewScopeIncludeClasses = new ArrayList<>();

    @JsonProperty("review_scope_exclude_classes")
    private List<String> reviewScopeExcludeClasses = new ArrayList<>();

    @JsonProperty("burp_dashboard_issue")
    private Map<String, Object> burpDashboardIssue = new LinkedHashMap<>();

    @JsonProperty("burp_related_scanner_issues")
    private List<Map<String, Object>> burpRelatedScannerIssues = new ArrayList<>();

    @JsonProperty("proxy_history_entries")
    private List<Map<String, Object>> proxyHistoryEntries = new ArrayList<>();

    @JsonProperty("logger_entries")
    private List<Map<String, Object>> loggerEntries = new ArrayList<>();

    @JsonProperty("repeater_requests")
    private List<Map<String, Object>> repeaterRequests = new ArrayList<>();

    @JsonProperty("project_config_snapshot")
    private Map<String, Object> projectConfigSnapshot = new LinkedHashMap<>();

    public AssessmentRequest() {
    }

    public AssessmentRequest(
            String rawRequest,
            String rawResponse,
            String targetUrl,
            String httpMethod,
            String sourceTool,
            boolean useBurpMcpContext,
            List<String> annotations,
            String batchId,
            Integer batchIndex,
            Integer batchTotal,
            Map<String, String> operatorAnswers,
            String toolHelpText,
            String scopeIncludesText,
            String scopeExcludesText,
            String rateLimitText,
            String maxConcurrencyText,
            String customHeadersText,
            String programPolicyText,
            String toolResultsText,
            String burpConfigExportText,
            String burpScreenshotAuditText,
            String loadedBurpToolsText,
            String savedProgramPolicyText,
            String programScreenshotAuditText,
            String responseDeltaText,
            List<String> evidenceTimelineEntries,
            List<String> issueWorkflowNotes,
            String investigationNotebookText,
            String bappFindingsText,
            String loggerEvidenceText,
            String collaboratorEvidenceText,
            String privacyModeOverride,
            String selectedProfile,
            List<String> reviewScopeIncludeClasses,
            List<String> reviewScopeExcludeClasses,
            Map<String, Object> burpDashboardIssue,
            List<Map<String, Object>> burpRelatedScannerIssues,
            List<Map<String, Object>> proxyHistoryEntries,
            List<Map<String, Object>> loggerEntries,
            List<Map<String, Object>> repeaterRequests,
            Map<String, Object> projectConfigSnapshot
    ) {
        this.rawRequest = rawRequest;
        this.rawResponse = rawResponse;
        this.targetUrl = targetUrl;
        this.httpMethod = httpMethod;
        this.sourceTool = sourceTool;
        this.useBurpMcpContext = useBurpMcpContext;
        setAnnotations(annotations);
        this.batchId = batchId;
        this.batchIndex = batchIndex;
        this.batchTotal = batchTotal;
        setOperatorAnswers(operatorAnswers);
        this.toolHelpText = toolHelpText;
        this.scopeIncludesText = scopeIncludesText;
        this.scopeExcludesText = scopeExcludesText;
        this.rateLimitText = rateLimitText;
        this.maxConcurrencyText = maxConcurrencyText;
        this.customHeadersText = customHeadersText;
        this.programPolicyText = programPolicyText;
        this.toolResultsText = toolResultsText;
        this.burpConfigExportText = burpConfigExportText;
        this.burpScreenshotAuditText = burpScreenshotAuditText;
        this.loadedBurpToolsText = loadedBurpToolsText;
        this.savedProgramPolicyText = savedProgramPolicyText;
        this.programScreenshotAuditText = programScreenshotAuditText;
        this.responseDeltaText = responseDeltaText;
        setEvidenceTimelineEntries(evidenceTimelineEntries);
        setIssueWorkflowNotes(issueWorkflowNotes);
        this.investigationNotebookText = investigationNotebookText;
        this.bappFindingsText = bappFindingsText;
        this.loggerEvidenceText = loggerEvidenceText;
        this.collaboratorEvidenceText = collaboratorEvidenceText;
        this.privacyModeOverride = privacyModeOverride;
        this.selectedProfile = selectedProfile;
        setReviewScopeIncludeClasses(reviewScopeIncludeClasses);
        setReviewScopeExcludeClasses(reviewScopeExcludeClasses);
        setBurpDashboardIssue(burpDashboardIssue);
        setBurpRelatedScannerIssues(burpRelatedScannerIssues);
        setProxyHistoryEntries(proxyHistoryEntries);
        setLoggerEntries(loggerEntries);
        setRepeaterRequests(repeaterRequests);
        setProjectConfigSnapshot(projectConfigSnapshot);
    }

    public AssessmentRequest copy() {
        return new AssessmentRequest(
                rawRequest,
                rawResponse,
                targetUrl,
                httpMethod,
                sourceTool,
                useBurpMcpContext,
                annotations,
                batchId,
                batchIndex,
                batchTotal,
                operatorAnswers,
                toolHelpText,
                scopeIncludesText,
                scopeExcludesText,
                rateLimitText,
                maxConcurrencyText,
                customHeadersText,
                programPolicyText,
                toolResultsText,
                burpConfigExportText,
                burpScreenshotAuditText,
                loadedBurpToolsText,
                savedProgramPolicyText,
                programScreenshotAuditText,
                responseDeltaText,
                evidenceTimelineEntries,
                issueWorkflowNotes,
                investigationNotebookText,
                bappFindingsText,
                loggerEvidenceText,
                collaboratorEvidenceText,
                privacyModeOverride,
                selectedProfile,
                reviewScopeIncludeClasses,
                reviewScopeExcludeClasses,
                burpDashboardIssue,
                burpRelatedScannerIssues,
                proxyHistoryEntries,
                loggerEntries,
                repeaterRequests,
                projectConfigSnapshot
        );
    }

    public String getRawRequest() {
        return rawRequest;
    }

    public void setRawRequest(String rawRequest) {
        this.rawRequest = rawRequest;
    }

    public String getRawResponse() {
        return rawResponse;
    }

    public void setRawResponse(String rawResponse) {
        this.rawResponse = rawResponse;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getSourceTool() {
        return sourceTool;
    }

    public void setSourceTool(String sourceTool) {
        this.sourceTool = sourceTool;
    }

    public boolean isUseBurpMcpContext() {
        return useBurpMcpContext;
    }

    public void setUseBurpMcpContext(boolean useBurpMcpContext) {
        this.useBurpMcpContext = useBurpMcpContext;
    }

    public List<String> getAnnotations() {
        return List.copyOf(annotations);
    }

    public void setAnnotations(List<String> annotations) {
        this.annotations = annotations == null ? new ArrayList<>() : new ArrayList<>(annotations);
    }

    public String getBatchId() {
        return batchId;
    }

    public void setBatchId(String batchId) {
        this.batchId = batchId;
    }

    public Integer getBatchIndex() {
        return batchIndex;
    }

    public void setBatchIndex(Integer batchIndex) {
        this.batchIndex = batchIndex;
    }

    public Integer getBatchTotal() {
        return batchTotal;
    }

    public void setBatchTotal(Integer batchTotal) {
        this.batchTotal = batchTotal;
    }

    public Map<String, String> getOperatorAnswers() {
        return Map.copyOf(operatorAnswers);
    }

    public void setOperatorAnswers(Map<String, String> operatorAnswers) {
        this.operatorAnswers = operatorAnswers == null ? new LinkedHashMap<>() : new LinkedHashMap<>(operatorAnswers);
    }

    public String getToolHelpText() {
        return toolHelpText;
    }

    public void setToolHelpText(String toolHelpText) {
        this.toolHelpText = toolHelpText;
    }

    public String getScopeIncludesText() {
        return scopeIncludesText;
    }

    public void setScopeIncludesText(String scopeIncludesText) {
        this.scopeIncludesText = scopeIncludesText;
    }

    public String getScopeExcludesText() {
        return scopeExcludesText;
    }

    public void setScopeExcludesText(String scopeExcludesText) {
        this.scopeExcludesText = scopeExcludesText;
    }

    public String getRateLimitText() {
        return rateLimitText;
    }

    public void setRateLimitText(String rateLimitText) {
        this.rateLimitText = rateLimitText;
    }

    public String getMaxConcurrencyText() {
        return maxConcurrencyText;
    }

    public void setMaxConcurrencyText(String maxConcurrencyText) {
        this.maxConcurrencyText = maxConcurrencyText;
    }

    public String getCustomHeadersText() {
        return customHeadersText;
    }

    public void setCustomHeadersText(String customHeadersText) {
        this.customHeadersText = customHeadersText;
    }

    public String getProgramPolicyText() {
        return programPolicyText;
    }

    public void setProgramPolicyText(String programPolicyText) {
        this.programPolicyText = programPolicyText;
    }

    public String getToolResultsText() {
        return toolResultsText;
    }

    public void setToolResultsText(String toolResultsText) {
        this.toolResultsText = toolResultsText;
    }

    public String getBurpConfigExportText() {
        return burpConfigExportText;
    }

    public void setBurpConfigExportText(String burpConfigExportText) {
        this.burpConfigExportText = burpConfigExportText;
    }

    public String getBurpScreenshotAuditText() {
        return burpScreenshotAuditText;
    }

    public void setBurpScreenshotAuditText(String burpScreenshotAuditText) {
        this.burpScreenshotAuditText = burpScreenshotAuditText;
    }

    public String getLoadedBurpToolsText() {
        return loadedBurpToolsText;
    }

    public void setLoadedBurpToolsText(String loadedBurpToolsText) {
        this.loadedBurpToolsText = loadedBurpToolsText;
    }

    public String getSavedProgramPolicyText() {
        return savedProgramPolicyText;
    }

    public void setSavedProgramPolicyText(String savedProgramPolicyText) {
        this.savedProgramPolicyText = savedProgramPolicyText;
    }

    public String getProgramScreenshotAuditText() {
        return programScreenshotAuditText;
    }

    public void setProgramScreenshotAuditText(String programScreenshotAuditText) {
        this.programScreenshotAuditText = programScreenshotAuditText;
    }

    public String getResponseDeltaText() {
        return responseDeltaText;
    }

    public void setResponseDeltaText(String responseDeltaText) {
        this.responseDeltaText = responseDeltaText;
    }

    public List<String> getEvidenceTimelineEntries() {
        return List.copyOf(evidenceTimelineEntries);
    }

    public void setEvidenceTimelineEntries(List<String> evidenceTimelineEntries) {
        this.evidenceTimelineEntries = evidenceTimelineEntries == null
                ? new ArrayList<>()
                : new ArrayList<>(evidenceTimelineEntries);
    }

    public List<String> getIssueWorkflowNotes() {
        return List.copyOf(issueWorkflowNotes);
    }

    public void setIssueWorkflowNotes(List<String> issueWorkflowNotes) {
        this.issueWorkflowNotes = issueWorkflowNotes == null
                ? new ArrayList<>()
                : new ArrayList<>(issueWorkflowNotes);
    }

    public String getInvestigationNotebookText() {
        return investigationNotebookText;
    }

    public void setInvestigationNotebookText(String investigationNotebookText) {
        this.investigationNotebookText = investigationNotebookText;
    }

    public String getBappFindingsText() {
        return bappFindingsText;
    }

    public void setBappFindingsText(String bappFindingsText) {
        this.bappFindingsText = bappFindingsText;
    }

    public String getLoggerEvidenceText() {
        return loggerEvidenceText;
    }

    public void setLoggerEvidenceText(String loggerEvidenceText) {
        this.loggerEvidenceText = loggerEvidenceText;
    }

    public String getCollaboratorEvidenceText() {
        return collaboratorEvidenceText;
    }

    public void setCollaboratorEvidenceText(String collaboratorEvidenceText) {
        this.collaboratorEvidenceText = collaboratorEvidenceText;
    }

    public String getPrivacyModeOverride() {
        return privacyModeOverride;
    }

    public void setPrivacyModeOverride(String privacyModeOverride) {
        this.privacyModeOverride = privacyModeOverride;
    }

    public String getSelectedProfile() {
        return selectedProfile;
    }

    public void setSelectedProfile(String selectedProfile) {
        this.selectedProfile = selectedProfile;
    }

    public List<String> getReviewScopeIncludeClasses() {
        return List.copyOf(reviewScopeIncludeClasses);
    }

    public void setReviewScopeIncludeClasses(List<String> reviewScopeIncludeClasses) {
        this.reviewScopeIncludeClasses = reviewScopeIncludeClasses == null
                ? new ArrayList<>()
                : new ArrayList<>(reviewScopeIncludeClasses);
    }

    public List<String> getReviewScopeExcludeClasses() {
        return List.copyOf(reviewScopeExcludeClasses);
    }

    public void setReviewScopeExcludeClasses(List<String> reviewScopeExcludeClasses) {
        this.reviewScopeExcludeClasses = reviewScopeExcludeClasses == null
                ? new ArrayList<>()
                : new ArrayList<>(reviewScopeExcludeClasses);
    }

    public Map<String, Object> getBurpDashboardIssue() {
        return shallowCopyMap(burpDashboardIssue);
    }

    public void setBurpDashboardIssue(Map<String, Object> burpDashboardIssue) {
        this.burpDashboardIssue = shallowCopyMap(burpDashboardIssue);
    }

    public List<Map<String, Object>> getBurpRelatedScannerIssues() {
        return shallowCopyListOfMaps(burpRelatedScannerIssues);
    }

    public void setBurpRelatedScannerIssues(List<Map<String, Object>> burpRelatedScannerIssues) {
        this.burpRelatedScannerIssues = shallowCopyListOfMaps(burpRelatedScannerIssues);
    }

    public List<Map<String, Object>> getProxyHistoryEntries() {
        return shallowCopyListOfMaps(proxyHistoryEntries);
    }

    public void setProxyHistoryEntries(List<Map<String, Object>> proxyHistoryEntries) {
        this.proxyHistoryEntries = shallowCopyListOfMaps(proxyHistoryEntries);
    }

    public List<Map<String, Object>> getLoggerEntries() {
        return shallowCopyListOfMaps(loggerEntries);
    }

    public void setLoggerEntries(List<Map<String, Object>> loggerEntries) {
        this.loggerEntries = shallowCopyListOfMaps(loggerEntries);
    }

    public List<Map<String, Object>> getRepeaterRequests() {
        return shallowCopyListOfMaps(repeaterRequests);
    }

    public void setRepeaterRequests(List<Map<String, Object>> repeaterRequests) {
        this.repeaterRequests = shallowCopyListOfMaps(repeaterRequests);
    }

    public Map<String, Object> getProjectConfigSnapshot() {
        return shallowCopyMap(projectConfigSnapshot);
    }

    public void setProjectConfigSnapshot(Map<String, Object> projectConfigSnapshot) {
        this.projectConfigSnapshot = shallowCopyMap(projectConfigSnapshot);
    }

    private static Map<String, Object> shallowCopyMap(Map<String, Object> source) {
        return source == null ? new LinkedHashMap<>() : new LinkedHashMap<>(source);
    }

    private static List<Map<String, Object>> shallowCopyListOfMaps(List<Map<String, Object>> source) {
        List<Map<String, Object>> copies = new ArrayList<>();
        if (source == null) {
            return copies;
        }
        for (Map<String, Object> item : source) {
            copies.add(shallowCopyMap(item));
        }
        return copies;
    }
}
