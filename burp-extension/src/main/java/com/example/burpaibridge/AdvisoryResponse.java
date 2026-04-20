package com.example.burpaibridge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class AdvisoryResponse {
    @JsonProperty("analysis")
    private String analysis;

    @JsonProperty("analysis_backend")
    private String analysisBackend;

    @JsonProperty("model_execution_summary")
    private String modelExecutionSummary;

    @JsonProperty("primary_next_action")
    private String primaryNextAction;

    @JsonProperty("request_plan")
    private List<String> requestPlan = new ArrayList<>();

    @JsonProperty("tool_availability_summary")
    private String toolAvailabilitySummary;

    @JsonProperty("potential_vulnerabilities")
    private List<String> potentialVulnerabilities = new ArrayList<>();

    @JsonProperty("nuclei_tags")
    private String nucleiTags;

    @JsonProperty("seclists_path")
    private String seclistsPath;

    @JsonProperty("questions_for_user")
    private List<String> questionsForUser = new ArrayList<>();

    @JsonProperty("source_links")
    private List<String> sourceLinks = new ArrayList<>();

    @JsonProperty("manual_tooling")
    private List<String> manualTooling = new ArrayList<>();

    @JsonProperty("manual_commands")
    private List<String> manualCommands = new ArrayList<>();

    @JsonProperty("payload_recommendations")
    private List<String> payloadRecommendations = new ArrayList<>();

    @JsonProperty("bcheck_recommendations")
    private List<String> bcheckRecommendations = new ArrayList<>();

    @JsonProperty("impact_paths")
    private List<String> impactPaths = new ArrayList<>();

    @JsonProperty("burp_settings_recommendations")
    private List<String> burpSettingsRecommendations = new ArrayList<>();

    @JsonProperty("project_readiness_summary")
    private String projectReadinessSummary;

    @JsonProperty("project_readiness_checks")
    private List<String> projectReadinessChecks = new ArrayList<>();

    @JsonProperty("burp_action_checklist")
    private List<String> burpActionChecklist = new ArrayList<>();

    @JsonProperty("burp_screenshot_review_status")
    private String burpScreenshotReviewStatus;

    @JsonProperty("suggestion_queue")
    private List<String> suggestionQueue = new ArrayList<>();

    @JsonProperty("confidence_by_class")
    private List<String> confidenceByClass = new ArrayList<>();

    @JsonProperty("history_correlation")
    private List<String> historyCorrelation = new ArrayList<>();

    @JsonProperty("confirmation_playbooks")
    private List<String> confirmationPlaybooks = new ArrayList<>();

    public AdvisoryResponse() {
    }

    public String getAnalysis() {
        return analysis == null || analysis.isBlank()
                ? "The backend did not return an analysis summary."
                : analysis;
    }

    public void setAnalysis(String analysis) {
        this.analysis = analysis;
    }

    public String getAnalysisBackend() {
        return analysisBackend == null ? "" : analysisBackend;
    }

    public void setAnalysisBackend(String analysisBackend) {
        this.analysisBackend = analysisBackend;
    }

    public String getModelExecutionSummary() {
        return modelExecutionSummary == null ? "" : modelExecutionSummary;
    }

    public void setModelExecutionSummary(String modelExecutionSummary) {
        this.modelExecutionSummary = modelExecutionSummary;
    }

    public String getPrimaryNextAction() {
        return primaryNextAction == null || primaryNextAction.isBlank()
                ? "No primary next action was returned."
                : primaryNextAction;
    }

    public void setPrimaryNextAction(String primaryNextAction) {
        this.primaryNextAction = primaryNextAction;
    }

    public List<String> getRequestPlan() {
        return requestPlan == null ? List.of() : List.copyOf(requestPlan);
    }

    public void setRequestPlan(List<String> requestPlan) {
        this.requestPlan = requestPlan == null ? new ArrayList<>() : new ArrayList<>(requestPlan);
    }

    public String getToolAvailabilitySummary() {
        return toolAvailabilitySummary == null ? "" : toolAvailabilitySummary;
    }

    public void setToolAvailabilitySummary(String toolAvailabilitySummary) {
        this.toolAvailabilitySummary = toolAvailabilitySummary;
    }

    public List<String> getPotentialVulnerabilities() {
        return potentialVulnerabilities == null ? List.of() : List.copyOf(potentialVulnerabilities);
    }

    public void setPotentialVulnerabilities(List<String> potentialVulnerabilities) {
        this.potentialVulnerabilities = potentialVulnerabilities == null
                ? new ArrayList<>()
                : new ArrayList<>(potentialVulnerabilities);
    }

    public String getNucleiTags() {
        return nucleiTags == null || nucleiTags.isBlank() ? "No nuclei tags suggested." : nucleiTags;
    }

    public void setNucleiTags(String nucleiTags) {
        this.nucleiTags = nucleiTags;
    }

    public String getSeclistsPath() {
        return seclistsPath == null || seclistsPath.isBlank() ? "No SecLists path suggested." : seclistsPath;
    }

    public void setSeclistsPath(String seclistsPath) {
        this.seclistsPath = seclistsPath;
    }

    public List<String> getQuestionsForUser() {
        return questionsForUser == null ? List.of() : List.copyOf(questionsForUser);
    }

    public void setQuestionsForUser(List<String> questionsForUser) {
        this.questionsForUser = questionsForUser == null ? new ArrayList<>() : new ArrayList<>(questionsForUser);
    }

    public List<String> getSourceLinks() {
        return sourceLinks == null ? List.of() : List.copyOf(sourceLinks);
    }

    public void setSourceLinks(List<String> sourceLinks) {
        this.sourceLinks = sourceLinks == null ? new ArrayList<>() : new ArrayList<>(sourceLinks);
    }

    public List<String> getManualTooling() {
        return manualTooling == null ? List.of() : List.copyOf(manualTooling);
    }

    public void setManualTooling(List<String> manualTooling) {
        this.manualTooling = manualTooling == null ? new ArrayList<>() : new ArrayList<>(manualTooling);
    }

    public List<String> getManualCommands() {
        return manualCommands == null ? List.of() : List.copyOf(manualCommands);
    }

    public void setManualCommands(List<String> manualCommands) {
        this.manualCommands = manualCommands == null ? new ArrayList<>() : new ArrayList<>(manualCommands);
    }

    public List<String> getPayloadRecommendations() {
        return payloadRecommendations == null ? List.of() : List.copyOf(payloadRecommendations);
    }

    public void setPayloadRecommendations(List<String> payloadRecommendations) {
        this.payloadRecommendations = payloadRecommendations == null ? new ArrayList<>() : new ArrayList<>(payloadRecommendations);
    }

    public List<String> getBcheckRecommendations() {
        return bcheckRecommendations == null ? List.of() : List.copyOf(bcheckRecommendations);
    }

    public void setBcheckRecommendations(List<String> bcheckRecommendations) {
        this.bcheckRecommendations = bcheckRecommendations == null ? new ArrayList<>() : new ArrayList<>(bcheckRecommendations);
    }

    public List<String> getImpactPaths() {
        return impactPaths == null ? List.of() : List.copyOf(impactPaths);
    }

    public void setImpactPaths(List<String> impactPaths) {
        this.impactPaths = impactPaths == null ? new ArrayList<>() : new ArrayList<>(impactPaths);
    }

    public List<String> getBurpSettingsRecommendations() {
        return burpSettingsRecommendations == null ? List.of() : List.copyOf(burpSettingsRecommendations);
    }

    public void setBurpSettingsRecommendations(List<String> burpSettingsRecommendations) {
        this.burpSettingsRecommendations = burpSettingsRecommendations == null
                ? new ArrayList<>()
                : new ArrayList<>(burpSettingsRecommendations);
    }

    public String getProjectReadinessSummary() {
        return projectReadinessSummary == null || projectReadinessSummary.isBlank()
                ? "Project readiness has not been scored yet."
                : projectReadinessSummary;
    }

    public void setProjectReadinessSummary(String projectReadinessSummary) {
        this.projectReadinessSummary = projectReadinessSummary;
    }

    public List<String> getProjectReadinessChecks() {
        return projectReadinessChecks == null ? List.of() : List.copyOf(projectReadinessChecks);
    }

    public void setProjectReadinessChecks(List<String> projectReadinessChecks) {
        this.projectReadinessChecks = projectReadinessChecks == null
                ? new ArrayList<>()
                : new ArrayList<>(projectReadinessChecks);
    }

    public List<String> getBurpActionChecklist() {
        return burpActionChecklist == null ? List.of() : List.copyOf(burpActionChecklist);
    }

    public void setBurpActionChecklist(List<String> burpActionChecklist) {
        this.burpActionChecklist = burpActionChecklist == null
                ? new ArrayList<>()
                : new ArrayList<>(burpActionChecklist);
    }

    public String getBurpScreenshotReviewStatus() {
        return burpScreenshotReviewStatus == null || burpScreenshotReviewStatus.isBlank()
                ? "No screenshot vision review was performed."
                : burpScreenshotReviewStatus;
    }

    public void setBurpScreenshotReviewStatus(String burpScreenshotReviewStatus) {
        this.burpScreenshotReviewStatus = burpScreenshotReviewStatus;
    }

    public List<String> getSuggestionQueue() {
        return suggestionQueue == null ? List.of() : List.copyOf(suggestionQueue);
    }

    public void setSuggestionQueue(List<String> suggestionQueue) {
        this.suggestionQueue = suggestionQueue == null ? new ArrayList<>() : new ArrayList<>(suggestionQueue);
    }

    public List<String> getConfidenceByClass() {
        return confidenceByClass == null ? List.of() : List.copyOf(confidenceByClass);
    }

    public void setConfidenceByClass(List<String> confidenceByClass) {
        this.confidenceByClass = confidenceByClass == null ? new ArrayList<>() : new ArrayList<>(confidenceByClass);
    }

    public List<String> getHistoryCorrelation() {
        return historyCorrelation == null ? List.of() : List.copyOf(historyCorrelation);
    }

    public void setHistoryCorrelation(List<String> historyCorrelation) {
        this.historyCorrelation = historyCorrelation == null ? new ArrayList<>() : new ArrayList<>(historyCorrelation);
    }

    public List<String> getConfirmationPlaybooks() {
        return confirmationPlaybooks == null ? List.of() : List.copyOf(confirmationPlaybooks);
    }

    public void setConfirmationPlaybooks(List<String> confirmationPlaybooks) {
        this.confirmationPlaybooks = confirmationPlaybooks == null ? new ArrayList<>() : new ArrayList<>(confirmationPlaybooks);
    }
}
