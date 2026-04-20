package com.example.burpaibridge;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.bchecks.BCheckImportResult;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class BurpAiBridgeExtension implements BurpExtension {
    private static final String DEFAULT_ENDPOINT = "http://127.0.0.1:8000/api/analyze";
    private static final String COLLABORATOR_SECRET_KEY = "aiBridge.collaborator.secret";
    private static final String COLLABORATOR_CUSTOM_DATA = "aibridge";
    private static final String PROJECT_SETTINGS_ROOT_KEY = "aiBridge.projectSettings";
    private static final String SETTINGS_BURP_CONFIG_EXPORT = "burpConfigExport";
    private static final String SETTINGS_BURP_SCREENSHOT_AUDIT = "burpScreenshotAudit";
    private static final String SETTINGS_LOADED_BURP_TOOLS = "loadedBurpTools";
    private static final String SETTINGS_PROGRAM_POLICY = "programPolicy";
    private static final String SETTINGS_PROGRAM_SCREENSHOT_AUDIT = "programScreenshotAudit";
    private static final String SETTINGS_AUTO_USE = "autoUseSavedSettings";
    private static final String SETTINGS_REUSE_REPEATER_INVESTIGATIONS = "reuseRepeaterInvestigations";
    private static final String SETTINGS_INVESTIGATION_STATES_JSON = "investigationStatesJson";
    private static final String SETTINGS_ACTIVE_INVESTIGATION_ID = "activeInvestigationId";
    private static final String SUGGESTION_FOLLOW_UP_KEY = "Suggestion follow-up request";
    private static final Pattern VULN_CLASS_PATTERN = Pattern.compile("^\\[(.+?)]\\s+");
    private static final int MAX_AUTO_ISSUES = 6;
    private static final int MAX_AUTO_INTERACTIONS = 8;
    private static final int MAX_RECENT_SCAN_ISSUES = 12;
    private static final long AUTO_SCAN_DEBOUNCE_MILLIS = 5000L;
    private static final int STARTUP_HEALTHCHECK_ATTEMPTS = 8;
    private static final long STARTUP_HEALTHCHECK_DELAY_MILLIS = 1500L;
    private static final boolean AUTO_SCAN_TRIAGE_ENABLED = false;
    private static final Pattern URL_PATTERN = Pattern.compile("(https?://\\S+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern HEADER_NAME_PATTERN = Pattern.compile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$");

    private MontoyaApi api;
    private ResultsTab resultsTab;
    private BridgeClient bridgeClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private AssessmentRequest latestSinglePayload;
    private final Map<String, AssessmentRequest> investigationPayloads = new LinkedHashMap<>();
    private String activeInvestigationId;
    private CompletableFuture<AdvisoryResponse> activeOperatorFollowUpFuture;
    private long activeOperatorFollowUpToken;
    private String activeOperatorFollowUpSessionId = "";
    private final Map<String, CompletableFuture<AdvisoryResponse>> activeInvestigationFollowUps = new ConcurrentHashMap<>();
    private final Map<String, Long> activeInvestigationFollowUpTokens = new ConcurrentHashMap<>();
    private final AtomicLong followUpTokenSequence = new AtomicLong();
    private CollaboratorClient collaboratorClient;
    private String latestCollaboratorPayload;
    private final List<AuditIssue> recentScanIssues = new ArrayList<>();
    private final Object scanIssueLock = new Object();
    private final List<AuditIssue> pendingAutoScanIssues = new ArrayList<>();
    private final Object autoScanLock = new Object();
    private final ScheduledExecutorService autoScanScheduler = Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture<?> scheduledAutoScanFlush;
    private CompletableFuture<AdvisoryResponse> activeAutoScanFuture;
    private String latestAutoScanSummary = "Automatic scan triage is disabled. Use 'Review Recent Findings' or 'Review This Target' to send scanner issues to AI Bridge.";
    private String latestAutoScanStatus = "Burp scan monitoring is active. AI Bridge will track scanner issues, but it will only analyze them when you explicitly review them.";
    private Crawl activeCrawlTask;
    private Audit activeAuditTask;
    private final Object burpSettingsLock = new Object();
    private Registration burpHeaderAutomationRegistration;
    private Map<String, String> activeBurpHeaderRules = Map.of();
    private List<String> activeScopeIncludePrefixes = List.of();
    private List<String> activeScopeExcludePrefixes = List.of();
    private Map<String, Boolean> appliedScopeState = Map.of();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.bridgeClient = new BridgeClient();

        api.extension().setName("AI Bridge");

        this.resultsTab = new ResultsTab(DEFAULT_ENDPOINT);
        this.resultsTab.setFeedbackSubmitter(this::submitFeedbackAsync);
        this.resultsTab.setFollowUpSubmitter(this::submitOperatorFollowUpAsync);
        this.resultsTab.setFollowUpCanceler(this::cancelOperatorFollowUpAsync);
        this.resultsTab.setInvestigationChatSubmitter(this::submitInvestigationChatAsync);
        this.resultsTab.setInvestigationSelectionListener(this::setActiveInvestigation);
        this.resultsTab.setInvestigationRepeaterSender(this::sendInvestigationDraftToRepeater);
        this.resultsTab.setInvestigationRenameListener(this::handleInvestigationRename);
        this.resultsTab.setInvestigationCloseListener(this::handleInvestigationClosed);
        this.resultsTab.setRepeaterReuseSettingListener(this::persistRepeaterReuseSetting);
        this.resultsTab.setToolInventoryRefresher(this::refreshToolInventoryAsync);
        this.resultsTab.setCollaboratorSyncer(this::syncCollaboratorClientAsync);
        this.resultsTab.setCollaboratorRotator(this::rotateCollaboratorClientAsync);
        this.resultsTab.setRecentScanAnalyzer(this::analyzeRecentScanIssuesAsync);
        this.resultsTab.setCurrentTargetScanAnalyzer(this::analyzeCurrentTargetScanIssuesAsync);
        this.resultsTab.setBcheckCatalogOpener(this::openBcheckCatalogAsync);
        this.resultsTab.setBurpSettingsApplier(this::applyBurpSettingsAsync);
        this.resultsTab.setBurpSettingsDisabler(this::disableBurpSettingsAutomationAsync);
        this.resultsTab.setAiBridgeSettingsSaver(this::saveAiBridgeProjectSettings);
        this.resultsTab.setAiBridgeSettingsReloader(this::reloadAiBridgeProjectSettings);
        this.resultsTab.setAiBridgeSettingsClearer(this::clearAiBridgeProjectSettings);
        this.resultsTab.setScanLauncher(this::launchBurpScanAsync);
        this.resultsTab.showAiBridgeSettingsProject(currentProjectLabel());
        api.userInterface().registerSuiteTab(resultsTab.caption(), resultsTab.uiComponent());
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                Optional<HttpRequestResponse> requestResponse = extractRequestResponse(event);
                List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
                List<AuditIssue> selectedIssues = new ArrayList<>(event.selectedIssues());
                if (requestResponse.isEmpty() && selected.isEmpty() && selectedIssues.isEmpty()) {
                    return List.of();
                }

                List<Component> items = new ArrayList<>();
                if (requestResponse.isPresent() || !selected.isEmpty()) {
                    JMenuItem sendToAiItem = new JMenuItem("Send " + describeRequestOrigin(event) + " to AI Bridge");
                    sendToAiItem.addActionListener(ignored -> {
                        HttpRequestResponse single = requestResponse.orElseGet(() -> selected.get(0));
                        analyzeRequestAsync(single, event.toolType(), event.invocationType());
                    });
                    items.add(sendToAiItem);
                }

                if (selected.size() > 1) {
                    JMenuItem batchItem = new JMenuItem("Analyze Selected In Batch");
                    batchItem.addActionListener(ignored -> analyzeBatchAsync(selected, event.toolType(), event.invocationType()));
                    items.add(batchItem);
                }

                if (!selectedIssues.isEmpty()) {
                    String label = selectedIssues.size() == 1
                            ? "Send Selected " + describeIssueOrigin(event) + " to AI Bridge"
                            : "Send Selected " + describeIssueOrigin(event) + "s to AI Bridge";
                    JMenuItem issueItem = new JMenuItem(label);
                    issueItem.addActionListener(ignored -> analyzeAuditIssuesAsync(selectedIssues, event.toolType(), event.invocationType()));
                    items.add(issueItem);
                }

                return items;
            }
        });
        api.scanner().registerPassiveScanCheck(new PassiveScanCheck() {
            @Override
            public String checkName() {
                return "AI Bridge Passive Scan Hook";
            }

            @Override
            public AuditResult doCheck(HttpRequestResponse requestResponse) {
                return AuditResult.auditResult();
            }
        }, ScanCheckType.PER_REQUEST);
        api.scanner().registerActiveScanCheck(new ActiveScanCheck() {
            @Override
            public String checkName() {
                return "AI Bridge Active Scan Hook";
            }

            @Override
            public AuditResult doCheck(HttpRequestResponse requestResponse, AuditInsertionPoint auditInsertionPoint, Http http) {
                return AuditResult.auditResult();
            }
        }, ScanCheckType.PER_INSERTION_POINT);
        api.scanner().registerAuditIssueHandler(new AuditIssueHandler() {
            @Override
            public void handleNewAuditIssue(AuditIssue auditIssue) {
                recordScanIssue(auditIssue);
            }
        });

        api.logging().logToOutput("AI Bridge loaded. Advisory workflow enabled.");
        initializeCollaboratorClient();
        reloadAiBridgeProjectSettings();
        restoreInvestigationSessions();
        refreshScanBridgeState("Burp scanner monitoring is active. Scanner issues are tracked for manual AI Bridge review only.");
        refreshToolInventoryAfterBackendReadyAsync();
    }

    private void analyzeBatchAsync(List<HttpRequestResponse> requestResponses, ToolType toolType, InvocationType invocationType) {
        cancelActiveOperatorFollowUp(false);
        latestSinglePayload = null;
        refreshScanBridgeState("Batch mode active. Analyze a single request or issue to enable current-target scan findings.");
        String batchId = UUID.randomUUID().toString();
        List<AssessmentRequest> payloads = new ArrayList<>();
        for (int index = 0; index < requestResponses.size(); index++) {
            payloads.add(buildPayload(requestResponses.get(index), batchId, index + 1, requestResponses.size(), toolType, invocationType));
        }
        BatchAccumulator accumulator = new BatchAccumulator(batchId, payloads.size());

        resultsTab.showBatchQueued(payloads.size());
        api.logging().logToOutput("Submitting batch to AI Bridge: " + payloads.size() + " requests.");

        java.util.concurrent.CompletableFuture.runAsync(() -> {
            for (int index = 0; index < payloads.size(); index++) {
                AssessmentRequest payload = payloads.get(index);
                int current = index + 1;
                try {
                    AdvisoryResponse response = bridgeClient.analyze(
                            resultsTab.endpointUrl(),
                            payload,
                            status -> resultsTab.showBatchProgress(current, payloads.size(), payload, status)
                    );
                    accumulator.recordSuccess(payload, response);
                    api.logging().logToOutput("AI Bridge batch item completed for " + payload.getTargetUrl());
                } catch (Exception exception) {
                    String message = rootCauseMessage(exception);
                    accumulator.recordFailure(payload, message);
                    api.logging().logToError("AI Bridge batch item failed for " + payload.getTargetUrl() + ": " + message);
                }
            }

            resultsTab.showBatchSummary(
                    accumulator.totalRequests,
                    accumulator.completedRequests,
                    accumulator.summaryText(),
                    accumulator.groupedFindingsText(),
                    accumulator.combinedTags(),
                    accumulator.suggestedWordlist(),
                    accumulator.followUpQuestions(),
                    accumulator.sourceLinksText()
            );
        }).exceptionally(error -> {
            String message = rootCauseMessage(error);
            api.logging().logToError("AI Bridge batch execution failed: " + message);
            resultsTab.showError(message);
            return null;
        });
    }

    private void analyzeRequestAsync(HttpRequestResponse requestResponse, ToolType toolType, InvocationType invocationType) {
        cancelActiveOperatorFollowUp(false);
        AssessmentRequest payload = buildPayload(requestResponse, null, 0, 0, toolType, invocationType);
        boolean reusedSession = toolType == ToolType.REPEATER && !findRepeaterSessionId(payload).isBlank();
        String sessionId = prepareInvestigationSession(payload, toolType, false, List.of());
        latestSinglePayload = payload;
        resultsTab.setCurrentScanTarget(payload.getTargetUrl());
        refreshScanBridgeState("Current target set to " + payload.getTargetUrl() + ". Burp scan findings can now be sent to AI Bridge.");
        resultsTab.showPendingAssessment(payload);
        resultsTab.showInvestigationQueued(sessionId, defaultInvestigationTitle(payload, toolType, List.of()), payload, reusedSession);
        persistInvestigationSessions();
        api.logging().logToOutput("Submitting traffic to AI Bridge for advisory analysis: " + payload.getTargetUrl());

        bridgeClient.analyzeAsync(resultsTab.endpointUrl(), payload, status -> {
                    resultsTab.showJobProgress(payload, status);
                    resultsTab.showInvestigationProgress(sessionId, payload, status);
                    api.logging().logToOutput(
                            "AI Bridge job " + status.getJobId() + " status: " + status.getStatus()
                    );
                })
                .whenComplete((response, error) -> {
                    if (error != null) {
                        String message = rootCauseMessage(error);
                        api.logging().logToError("AI Bridge request failed: " + message);
                        resultsTab.showInvestigationError(sessionId, message);
                        resultsTab.showError(message);
                        return;
                    }

                    investigationPayloads.put(sessionId, payload.copy());
                    setActiveInvestigation(sessionId);
                    resultsTab.updateResults(response, payload);
                    refreshReasoningAsync(resultsTab.currentJobId());
                    resultsTab.updateInvestigationTitle(sessionId, titleWithFindingHeader(payload, response, defaultInvestigationTitle(payload, toolType, List.of())));
                    resultsTab.showInvestigationResult(sessionId, payload, response);
                    persistInvestigationSessions();
                    latestSinglePayload = payload;
                    api.logging().logToOutput("AI Bridge response received for " + payload.getTargetUrl());
                });
    }

    private void analyzeAuditIssuesAsync(List<AuditIssue> issues, ToolType toolType, InvocationType invocationType) {
        cancelActiveOperatorFollowUp(false);
        AssessmentRequest payload = buildPayloadFromIssues(issues, toolType, invocationType);
        String sessionId = prepareInvestigationSession(payload, toolType, true, issues);
        latestSinglePayload = payload;
        resultsTab.setCurrentScanTarget(payload.getTargetUrl());
        refreshScanBridgeState("Current target set from selected Burp issue(s): " + payload.getTargetUrl());
        resultsTab.showPendingAssessment(payload);
        resultsTab.showInvestigationQueued(sessionId, defaultInvestigationTitle(payload, toolType, issues), payload, false);
        persistInvestigationSessions();
        api.logging().logToOutput(
                "Submitting " + issues.size() + " selected Burp audit issue(s) to AI Bridge for " + payload.getTargetUrl()
        );

        bridgeClient.analyzeAsync(resultsTab.endpointUrl(), payload, status -> {
                    resultsTab.showJobProgress(payload, status);
                    resultsTab.showInvestigationProgress(sessionId, payload, status);
                    api.logging().logToOutput(
                            "AI Bridge audit-issue job " + status.getJobId() + " status: " + status.getStatus()
                    );
                })
                .whenComplete((response, error) -> {
                    if (error != null) {
                        String message = rootCauseMessage(error);
                        api.logging().logToError("AI Bridge audit-issue request failed: " + message);
                        resultsTab.showInvestigationError(sessionId, message);
                        resultsTab.showError(message);
                        return;
                    }

                    investigationPayloads.put(sessionId, payload.copy());
                    setActiveInvestigation(sessionId);
                    resultsTab.showBackendHealthy("Backend healthy. Last AI response received successfully.");
                    resultsTab.updateResults(response, payload);
                    refreshReasoningAsync(resultsTab.currentJobId());
                    resultsTab.updateInvestigationTitle(sessionId, titleWithFindingHeader(payload, response, defaultInvestigationTitle(payload, toolType, issues)));
                    resultsTab.showInvestigationResult(sessionId, payload, response);
                    persistInvestigationSessions();
                    latestSinglePayload = payload;
                    api.logging().logToOutput("AI Bridge audit-issue response received for " + payload.getTargetUrl());
                });
    }

    private void submitOperatorFollowUpAsync() {
        String sessionId = activeInvestigationId == null || activeInvestigationId.isBlank()
                ? resultsTab.activeInvestigationId()
                : activeInvestigationId;
        AssessmentRequest basePayload = sessionId == null || sessionId.isBlank()
                ? latestSinglePayload
                : investigationPayloads.getOrDefault(sessionId, latestSinglePayload);
        if (basePayload == null) {
            resultsTab.showFollowUpSubmissionError("No single request is loaded for follow-up analysis.");
            return;
        }

        AssessmentRequest payload = prepareFollowUpPayload(basePayload.copy(), sessionId, null);

        resultsTab.showFollowUpSubmitting();
        activeOperatorFollowUpSessionId = sessionId == null ? "" : sessionId;
        if (!activeOperatorFollowUpSessionId.isBlank()) {
            resultsTab.showInvestigationFollowUpSubmitting(activeOperatorFollowUpSessionId);
        }
        api.logging().logToOutput("Submitting AI Bridge follow-up with operator answers for " + payload.getTargetUrl());

        long followUpToken = followUpTokenSequence.incrementAndGet();
        activeOperatorFollowUpToken = followUpToken;
        try {
            activeOperatorFollowUpFuture = bridgeClient.analyzeAsync(resultsTab.endpointUrl(), payload, status -> {
                        if (followUpToken != activeOperatorFollowUpToken) {
                            return;
                        }
                        resultsTab.showJobProgress(payload, status);
                        if (sessionId != null && !sessionId.isBlank()) {
                            resultsTab.showInvestigationProgress(sessionId, payload, status);
                        }
                        api.logging().logToOutput(
                                "AI Bridge follow-up job " + status.getJobId() + " status: " + status.getStatus()
                        );
                    })
                    .whenComplete((response, error) -> {
                        if (followUpToken != activeOperatorFollowUpToken) {
                            return;
                        }
                        activeOperatorFollowUpFuture = null;
                        String finishedSessionId = activeOperatorFollowUpSessionId;
                        activeOperatorFollowUpSessionId = "";
                        if (error != null) {
                            String message = rootCauseMessage(error);
                            api.logging().logToError("AI Bridge follow-up failed: " + message);
                            if (!finishedSessionId.isBlank()) {
                                resultsTab.showInvestigationError(finishedSessionId, message);
                            }
                            resultsTab.showFollowUpSubmissionError(message);
                            return;
                        }

                        latestSinglePayload = payload;
                        resultsTab.showBackendHealthy("Backend healthy. Last AI response received successfully.");
                        resultsTab.updateResults(response, payload);
                        refreshReasoningAsync(resultsTab.currentJobId());
                        if (!finishedSessionId.isBlank()) {
                            investigationPayloads.put(finishedSessionId, payload.copy());
                            setActiveInvestigation(finishedSessionId);
                            resultsTab.updateInvestigationTitle(finishedSessionId, titleWithFindingHeader(payload, response, resultsTab.investigationTitle(finishedSessionId)));
                            resultsTab.showInvestigationResult(finishedSessionId, payload, response);
                            persistInvestigationSessions();
                        }
                        api.logging().logToOutput("AI Bridge follow-up response received for " + payload.getTargetUrl());
                    });
        } catch (Exception exception) {
            activeOperatorFollowUpFuture = null;
            String failedSessionId = activeOperatorFollowUpSessionId;
            activeOperatorFollowUpSessionId = "";
            String message = rootCauseMessage(exception);
            api.logging().logToError("AI Bridge follow-up failed before submission: " + message);
            if (!failedSessionId.isBlank()) {
                resultsTab.showInvestigationError(failedSessionId, message);
            }
            resultsTab.showFollowUpSubmissionError(message);
        }
    }

    private void submitInvestigationChatAsync(String sessionId, String prompt) {
        AssessmentRequest basePayload = investigationPayloads.get(sessionId);
        if (basePayload == null) {
            resultsTab.showInvestigationError(sessionId, "No investigation payload is loaded for this tab yet.");
            return;
        }

        AssessmentRequest payload = prepareFollowUpPayload(basePayload.copy(), sessionId, prompt);
        latestSinglePayload = payload;
        setActiveInvestigation(sessionId);
        api.logging().logToOutput("Submitting AI Bridge investigation follow-up for " + payload.getTargetUrl());

        long followUpToken = followUpTokenSequence.incrementAndGet();
        activeInvestigationFollowUpTokens.put(sessionId, followUpToken);
        try {
            CompletableFuture<AdvisoryResponse> sessionFuture = bridgeClient.analyzeAsync(resultsTab.endpointUrl(), payload, status -> {
                        Long activeToken = activeInvestigationFollowUpTokens.get(sessionId);
                        if (activeToken == null || followUpToken != activeToken) {
                            return;
                        }
                        resultsTab.showJobProgress(payload, status);
                        resultsTab.showInvestigationProgress(sessionId, payload, status);
                        api.logging().logToOutput(
                                "AI Bridge investigation job " + status.getJobId() + " status: " + status.getStatus()
                        );
                    })
                    .whenComplete((response, error) -> {
                        Long activeToken = activeInvestigationFollowUpTokens.get(sessionId);
                        if (activeToken == null || followUpToken != activeToken) {
                            return;
                        }
                        activeInvestigationFollowUps.remove(sessionId);
                        activeInvestigationFollowUpTokens.remove(sessionId);
                        if (error != null) {
                            String message = rootCauseMessage(error);
                            api.logging().logToError("AI Bridge investigation follow-up failed: " + message);
                            resultsTab.showInvestigationError(sessionId, message);
                            return;
                        }

                        investigationPayloads.put(sessionId, payload.copy());
                        latestSinglePayload = payload;
                        setActiveInvestigation(sessionId);
                        resultsTab.showBackendHealthy("Backend healthy. Last AI response received successfully.");
                        resultsTab.updateResults(response, payload);
                        refreshReasoningAsync(resultsTab.currentJobId());
                        resultsTab.updateInvestigationTitle(sessionId, titleWithFindingHeader(payload, response, resultsTab.investigationTitle(sessionId)));
                        resultsTab.showInvestigationResult(sessionId, payload, response);
                        persistInvestigationSessions();
                        api.logging().logToOutput("AI Bridge investigation follow-up response received for " + payload.getTargetUrl());
                    });
            activeInvestigationFollowUps.put(sessionId, sessionFuture);
        } catch (Exception exception) {
            activeInvestigationFollowUpTokens.remove(sessionId);
            String message = rootCauseMessage(exception);
            api.logging().logToError("AI Bridge investigation follow-up failed before submission: " + message);
            resultsTab.showInvestigationError(sessionId, message);
        }
    }

    private AssessmentRequest prepareFollowUpPayload(AssessmentRequest payload, String sessionId, String suggestionOverride) {
        List<String> annotations = new ArrayList<>(payload.getAnnotations());
        if (!annotations.contains("operator_followup")) {
            annotations.add("operator_followup");
        }
        payload.setAnnotations(annotations);
        applyOperatorRoutingAnnotations(payload);
        payload.setBatchId("");
        payload.setBatchIndex(0);
        payload.setBatchTotal(0);

        Map<String, String> answers = new LinkedHashMap<>(payload.getOperatorAnswers());
        mergeNonBlankAnswers(answers, resultsTab.operatorAnswersForSubmission());
        if (suggestionOverride != null && !suggestionOverride.isBlank()) {
            answers.put(SUGGESTION_FOLLOW_UP_KEY, suggestionOverride);
        }
        payload.setOperatorAnswers(answers);
        payload.setToolHelpText(preferCurrentText(resultsTab.toolHelpText(), payload.getToolHelpText()));
        payload.setScopeIncludesText(preferCurrentText(resultsTab.scopeIncludesText(), payload.getScopeIncludesText()));
        payload.setScopeExcludesText(preferCurrentText(resultsTab.scopeExcludesText(), payload.getScopeExcludesText()));
        payload.setRateLimitText(preferCurrentText(resultsTab.rateLimitText(), payload.getRateLimitText()));
        payload.setMaxConcurrencyText(preferCurrentText(resultsTab.maxConcurrencyText(), payload.getMaxConcurrencyText()));
        payload.setCustomHeadersText(preferCurrentText(resultsTab.customHeadersText(), payload.getCustomHeadersText()));
        payload.setResponseDeltaText(preferCurrentText(resultsTab.responseDeltaText(), payload.getResponseDeltaText()));
        payload.setProgramPolicyText(preferCurrentText(resultsTab.programPolicyText(), payload.getProgramPolicyText()));
        payload.setBappFindingsText(preferCurrentText(resultsTab.bappFindingsText(), payload.getBappFindingsText()));
        payload.setLoggerEvidenceText(preferCurrentText(resultsTab.loggerEvidenceText(), payload.getLoggerEvidenceText()));
        payload.setCollaboratorEvidenceText(preferCurrentText(resultsTab.collaboratorEvidenceText(), payload.getCollaboratorEvidenceText()));
        payload.setToolResultsText(preferCurrentText(resultsTab.toolResultsText(), payload.getToolResultsText()));
        payload.setBurpConfigExportText(resultsTab.effectiveBurpConfigExportText());
        payload.setBurpScreenshotAuditText(resultsTab.autoUseSavedSettings() ? resultsTab.burpScreenshotAuditText() : "");
        payload.setLoadedBurpToolsText(resultsTab.autoUseSavedSettings() ? resultsTab.savedBurpToolsText() : "");
        payload.setSavedProgramPolicyText(resultsTab.autoUseSavedSettings() ? resultsTab.savedProgramPolicyText() : "");
        payload.setProgramScreenshotAuditText(resultsTab.autoUseSavedSettings() ? resultsTab.savedProgramScreenshotText() : "");
        payload.setEvidenceTimelineEntries(preferCurrentList(resultsTab.evidenceTimelineEntries(), payload.getEvidenceTimelineEntries()));
        payload.setPrivacyModeOverride(resultsTab.privacyMode());
        payload.setSelectedProfile(resultsTab.selectedProfile());
        payload.setReviewScopeIncludeClasses(resultsTab.reviewScopeIncludeClasses());
        payload.setReviewScopeExcludeClasses(resultsTab.reviewScopeExcludeClasses());
        if (sessionId != null && !sessionId.isBlank()) {
            payload.setRawRequest(preferCurrentText(resultsTab.investigationRequestDraft(sessionId), payload.getRawRequest()));
            payload.setRawResponse(preferCurrentText(resultsTab.investigationResponseSnapshot(sessionId), payload.getRawResponse()));
            payload.setIssueWorkflowNotes(resultsTab.investigationWorkflowNotes(sessionId));
            payload.setInvestigationNotebookText(resultsTab.investigationCaseNotebookText(sessionId));
        }
        enrichPayloadWithBurpContext(payload);
        return payload;
    }

    private void applyOperatorRoutingAnnotations(AssessmentRequest payload) {
        if (payload == null) {
            return;
        }
        List<String> annotations = new ArrayList<>(payload.getAnnotations());
        annotations.removeIf(item -> item != null && item.toLowerCase(Locale.ROOT).startsWith("time_budget_"));
        String selectedBudget = resultsTab.selectedTimeBudgetAnnotation();
        if (selectedBudget != null && !selectedBudget.isBlank()) {
            annotations.add(selectedBudget);
        }
        payload.setAnnotations(annotations);
    }

    private String prepareInvestigationSession(
            AssessmentRequest payload,
            ToolType toolType,
            boolean issuePayload,
            List<AuditIssue> issues
    ) {
        String sessionId = !issuePayload
                && toolType == ToolType.REPEATER
                && resultsTab.reuseRepeaterInvestigations()
                ? findRepeaterSessionId(payload)
                : "";
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = UUID.randomUUID().toString();
        }
        investigationPayloads.put(sessionId, payload.copy());
        activeInvestigationId = sessionId;
        return sessionId;
    }

    private String findRepeaterSessionId(AssessmentRequest payload) {
        String fingerprint = repeaterFingerprint(payload);
        if (fingerprint.isBlank()) {
            return "";
        }
        for (Map.Entry<String, AssessmentRequest> entry : investigationPayloads.entrySet()) {
            AssessmentRequest existing = entry.getValue();
            if (existing == null) {
                continue;
            }
            if (fingerprint.equals(repeaterFingerprint(existing))) {
                return entry.getKey();
            }
        }
        return "";
    }

    private String repeaterFingerprint(AssessmentRequest payload) {
        if (payload == null) {
            return "";
        }
        String targetUrl = firstNonBlank(payload.getTargetUrl(), "").trim();
        String method = firstNonBlank(payload.getHttpMethod(), "").trim().toUpperCase();
        if (targetUrl.isBlank() || method.isBlank()) {
            return "";
        }
        try {
            URI uri = new URI(targetUrl);
            String host = firstNonBlank(uri.getHost(), "").toLowerCase();
            int port = uri.getPort();
            String effectivePort = port < 0 ? "" : ":" + port;
            String path = normalizeFingerprintPath(firstNonBlank(uri.getPath(), "/"));
            return method
                    + "|" + host + effectivePort
                    + "|" + path
                    + "|" + extractContentType(payload)
                    + "|" + queryKeyFingerprint(uri)
                    + "|" + bodyShapeFingerprint(payload)
                    + "|" + issueClassFingerprint(payload)
                    + "|" + insertionPointFingerprint(payload);
        } catch (URISyntaxException exception) {
            return method
                    + "|" + targetUrl
                    + "|" + extractContentType(payload)
                    + "|" + bodyShapeFingerprint(payload)
                    + "|" + issueClassFingerprint(payload)
                    + "|" + insertionPointFingerprint(payload);
        }
    }

    private String extractContentType(AssessmentRequest payload) {
        String rawRequest = firstNonBlank(payload.getRawRequest(), "");
        for (String line : rawRequest.replace("\r\n", "\n").split("\n")) {
            if (line.toLowerCase().startsWith("content-type:")) {
                return line.substring("content-type:".length()).trim().toLowerCase();
            }
        }
        return "";
    }

    private String queryKeyFingerprint(URI uri) {
        String query = firstNonBlank(uri.getQuery(), "");
        if (query.isBlank()) {
            return "";
        }
        TreeSet<String> names = new TreeSet<>();
        for (String pair : query.split("&")) {
            if (pair == null || pair.isBlank()) {
                continue;
            }
            int separator = pair.indexOf('=');
            String name = separator >= 0 ? pair.substring(0, separator) : pair;
            name = decodeFingerprintValue(name).trim().toLowerCase();
            if (!name.isBlank()) {
                names.add(name);
            }
        }
        return String.join(",", names);
    }

    private String bodyShapeFingerprint(AssessmentRequest payload) {
        String rawRequest = firstNonBlank(payload.getRawRequest(), "");
        String body = requestBody(rawRequest);
        if (body.isBlank()) {
            return "";
        }
        String contentType = extractContentType(payload);
        try {
            if (contentType.contains("json")) {
                var node = objectMapper.readTree(body);
                if (node != null && node.isObject()) {
                    TreeSet<String> keys = new TreeSet<>();
                    node.fieldNames().forEachRemaining(name -> {
                        if (name != null && !name.isBlank()) {
                            keys.add(name.toLowerCase());
                        }
                    });
                    return "json:" + String.join(",", keys);
                }
                return "json";
            }
        } catch (Exception ignored) {
            return "json";
        }

        if (contentType.contains("xml") || body.stripLeading().startsWith("<?xml") || body.stripLeading().startsWith("<")) {
            Matcher tagMatcher = Pattern.compile("<\\s*([A-Za-z0-9:_-]+)").matcher(body);
            TreeSet<String> tags = new TreeSet<>();
            while (tagMatcher.find() && tags.size() < 4) {
                String tag = tagMatcher.group(1);
                if (tag != null && !tag.isBlank() && !tag.startsWith("?") && !tag.equalsIgnoreCase("!doctype")) {
                    tags.add(tag.toLowerCase());
                }
            }
            return tags.isEmpty() ? "xml" : "xml:" + String.join(",", tags);
        }

        if (contentType.contains("application/x-www-form-urlencoded")) {
            TreeSet<String> names = new TreeSet<>();
            for (String pair : body.split("&")) {
                if (pair == null || pair.isBlank()) {
                    continue;
                }
                int separator = pair.indexOf('=');
                String name = separator >= 0 ? pair.substring(0, separator) : pair;
                name = decodeFingerprintValue(name).trim().toLowerCase();
                if (!name.isBlank()) {
                    names.add(name);
                }
            }
            return "form:" + String.join(",", names);
        }

        return compactBodyHint(body);
    }

    private String issueClassFingerprint(AssessmentRequest payload) {
        String combined = String.join(" ",
                firstNonBlank(payload.getToolResultsText(), ""),
                firstNonBlank(payload.getBappFindingsText(), ""),
                firstNonBlank(payload.getCollaboratorEvidenceText(), "")
        ).toLowerCase();
        TreeSet<String> classes = new TreeSet<>();
        if (combined.contains("xml external entity injection") || combined.contains(" xxe")) {
            classes.add("xxe");
        }
        if (combined.contains("server-side request forgery") || combined.contains(" ssrf")) {
            classes.add("ssrf");
        }
        if (combined.contains("sql injection") || combined.contains(" sqli")) {
            classes.add("sqli");
        }
        if (combined.contains("cross-site scripting") || combined.contains(" xss")) {
            classes.add("xss");
        }
        if (combined.contains("access control") || combined.contains(" idor")) {
            classes.add("access-control");
        }
        if (combined.contains("open redirect")) {
            classes.add("open-redirect");
        }
        if (combined.contains("path traversal")) {
            classes.add("path-traversal");
        }
        if (combined.contains("cross-site request forgery") || combined.contains(" csrf")) {
            classes.add("csrf");
        }
        if (combined.contains("collaborator dns interaction") || combined.contains("dns interaction")) {
            classes.add("dns-callback");
        }
        return String.join(",", classes);
    }

    private String insertionPointFingerprint(AssessmentRequest payload) {
        String combined = String.join(" ",
                firstNonBlank(payload.getToolResultsText(), ""),
                firstNonBlank(payload.getBappFindingsText(), "")
        ).toLowerCase();
        TreeSet<String> locations = new TreeSet<>();
        if (combined.contains("request body")) {
            locations.add("body");
        }
        if (combined.contains("query string") || combined.contains("query parameter")) {
            locations.add("query");
        }
        if (combined.contains("header")) {
            locations.add("header");
        }
        if (combined.contains("cookie")) {
            locations.add("cookie");
        }
        if (combined.contains("path")) {
            locations.add("path");
        }
        return String.join(",", locations);
    }

    private String requestBody(String rawRequest) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return "";
        }
        int separator = rawRequest.indexOf("\r\n\r\n");
        if (separator >= 0) {
            return rawRequest.substring(separator + 4).trim();
        }
        separator = rawRequest.indexOf("\n\n");
        if (separator >= 0) {
            return rawRequest.substring(separator + 2).trim();
        }
        return "";
    }

    private String compactBodyHint(String body) {
        String compact = firstNonBlank(body, "").replace("\r", " ").replace("\n", " ").trim().toLowerCase();
        if (compact.isBlank()) {
            return "";
        }
        return compact.length() <= 48 ? compact : compact.substring(0, 48).trim();
    }

    private String normalizeFingerprintPath(String path) {
        String normalized = firstNonBlank(path, "/").trim();
        if (normalized.isBlank()) {
            return "/";
        }
        normalized = normalized.replaceAll("/{2,}", "/");
        if (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String decodeFingerprintValue(String value) {
        String normalized = firstNonBlank(value, "");
        if (normalized.isBlank()) {
            return "";
        }
        try {
            return URLDecoder.decode(normalized, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException exception) {
            return normalized;
        }
    }

    private String defaultInvestigationTitle(AssessmentRequest payload, ToolType toolType, List<AuditIssue> issues) {
        String path = shortTargetPath(firstNonBlank(payload.getTargetUrl(), ""));
        if (issues != null && !issues.isEmpty()) {
            String issueName = compactIssueTitle(firstNonBlank(issues.get(0).name(), "Scanner issue"));
            if (issues.size() > 1) {
                issueName = issueName + " +" + (issues.size() - 1);
            }
            return issueName + " " + path;
        }

        String source = toolType == null ? "Request" : switch (toolType) {
            case REPEATER -> "Repeater";
            case INTRUDER -> "Intruder";
            case SCANNER -> "Scanner";
            default -> "Request";
        };
        return source + " " + firstNonBlank(payload.getHttpMethod(), "REQUEST") + " " + path;
    }

    private String titleWithFindingHeader(AssessmentRequest payload, AdvisoryResponse response, String fallbackTitle) {
        List<String> findings = response == null ? List.of() : response.getPotentialVulnerabilities();
        String path = shortTargetPath(firstNonBlank(payload == null ? "" : payload.getTargetUrl(), ""));
        if (!findings.isEmpty()) {
            String finding = findings.get(0);
            Matcher matcher = VULN_CLASS_PATTERN.matcher(firstNonBlank(finding, ""));
            if (matcher.find()) {
                return matcher.group(1).toUpperCase() + " " + path;
            }
        }
        return firstNonBlank(fallbackTitle, "Investigation");
    }

    private String compactIssueTitle(String issueName) {
        String normalized = firstNonBlank(issueName, "Issue").replace("XML external entity injection", "XXE");
        return normalized.length() <= 28 ? normalized : normalized.substring(0, 28).trim();
    }

    private String shortTargetPath(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return "/unknown";
        }
        try {
            URI uri = new URI(targetUrl);
            String path = firstNonBlank(uri.getPath(), "/");
            return path.isBlank() ? "/" : path;
        } catch (URISyntaxException exception) {
            int slashIndex = targetUrl.indexOf('/', targetUrl.indexOf("://") + 3);
            return slashIndex >= 0 ? targetUrl.substring(slashIndex) : targetUrl;
        }
    }

    private void setActiveInvestigation(String sessionId) {
        activeInvestigationId = firstNonBlank(sessionId, "");
        AssessmentRequest payload = investigationPayloads.get(activeInvestigationId);
        if (payload != null) {
            latestSinglePayload = payload;
        }
    }

    private void sendInvestigationDraftToRepeater(String sessionId) {
        String rawRequest = resultsTab.investigationRequestDraft(sessionId);
        if (rawRequest == null || rawRequest.isBlank()) {
            resultsTab.showInvestigationError(sessionId, "The investigation request draft is blank, so nothing was sent to Repeater.");
            return;
        }
        try {
            api.repeater().sendToRepeater(
                    HttpRequest.httpRequest(rawRequest),
                    firstNonBlank(resultsTab.investigationTitle(sessionId), "AI Bridge")
            );
            persistInvestigationSessions();
            api.logging().logToOutput("AI Bridge sent the investigation draft to Burp Repeater.");
        } catch (Exception exception) {
            String message = rootCauseMessage(exception);
            resultsTab.showInvestigationError(sessionId, "Unable to send the draft to Repeater: " + message);
            api.logging().logToError("AI Bridge could not send the investigation draft to Repeater: " + message);
        }
    }

    private void handleInvestigationRename(String sessionId, String title) {
        if (sessionId == null || sessionId.isBlank()) {
            return;
        }
        setActiveInvestigation(sessionId);
        persistInvestigationSessions();
    }

    private void handleInvestigationClosed(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return;
        }
        if (sessionId.equals(activeOperatorFollowUpSessionId)) {
            cancelActiveOperatorFollowUp(false);
        }
        cancelInvestigationFollowUp(sessionId, false);
        investigationPayloads.remove(sessionId);
        if (sessionId.equals(activeInvestigationId)) {
            activeInvestigationId = "";
        }
        persistInvestigationSessions();
    }

    private void persistRepeaterReuseSetting(boolean enabled) {
        try {
            PersistedObject settings = currentProjectSettingsObject(true);
            if (settings != null) {
                settings.setBoolean(SETTINGS_REUSE_REPEATER_INVESTIGATIONS, enabled);
            }
        } catch (Exception exception) {
            api.logging().logToError("Unable to persist AI Bridge Repeater reuse setting: " + rootCauseMessage(exception));
        }
    }

    private void restoreInvestigationSessions() {
        try {
            PersistedObject settings = currentProjectSettingsObject(false);
            if (settings == null) {
                return;
            }
            Boolean reuse = settings.getBoolean(SETTINGS_REUSE_REPEATER_INVESTIGATIONS);
            resultsTab.setReuseRepeaterInvestigations(reuse == null || reuse);

            String json = firstNonBlank(settings.getString(SETTINGS_INVESTIGATION_STATES_JSON), "");
            if (!json.isBlank()) {
                List<InvestigationSessionState> states = objectMapper.readValue(json, new TypeReference<List<InvestigationSessionState>>() {
                });
                Map<String, InvestigationSessionState> restoredStates = new LinkedHashMap<>();
                for (InvestigationSessionState state : states) {
                    if (state == null || state.sessionId == null || state.sessionId.isBlank() || state.payload == null) {
                        continue;
                    }
                    restoredStates.put(state.sessionId, state);
                    investigationPayloads.put(state.sessionId, state.payload);
                    resultsTab.restoreInvestigationSession(
                            state.sessionId,
                            state.title,
                            state.payload,
                            state.requestDraft,
                            state.chatTranscript,
                            state.transcriptEntries,
                            state.notebookEntries,
                            state.statusText,
                            false
                    );
                }
                String activeId = firstNonBlank(settings.getString(SETTINGS_ACTIVE_INVESTIGATION_ID), "");
                if (!activeId.isBlank() && investigationPayloads.containsKey(activeId)) {
                    InvestigationSessionState activeState = restoredStates.get(activeId);
                    setActiveInvestigation(activeId);
                    resultsTab.restoreInvestigationSession(
                            activeId,
                            resultsTab.investigationTitle(activeId),
                            investigationPayloads.get(activeId),
                            resultsTab.investigationRequestDraft(activeId),
                            resultsTab.investigationChatTranscript(activeId),
                            activeState == null ? List.of() : activeState.transcriptEntries,
                            activeState == null ? List.of() : activeState.notebookEntries,
                            activeState == null ? "" : activeState.statusText,
                            true
                    );
                }
            }
        } catch (Exception exception) {
            api.logging().logToError("Unable to restore AI Bridge investigations: " + rootCauseMessage(exception));
        }
    }

    private void persistInvestigationSessions() {
        try {
            PersistedObject settings = currentProjectSettingsObject(true);
            if (settings == null) {
                return;
            }
            List<InvestigationSessionState> states = new ArrayList<>();
            for (Map.Entry<String, AssessmentRequest> entry : investigationPayloads.entrySet()) {
                String sessionId = entry.getKey();
                AssessmentRequest payload = entry.getValue();
                if (payload == null) {
                    continue;
                }
                InvestigationSessionState state = new InvestigationSessionState();
                state.sessionId = sessionId;
                state.title = resultsTab.investigationTitle(sessionId);
                state.requestDraft = resultsTab.investigationRequestDraft(sessionId);
                state.chatTranscript = resultsTab.investigationChatTranscript(sessionId);
                state.transcriptEntries = resultsTab.investigationTranscriptEntries(sessionId);
                state.notebookEntries = resultsTab.investigationNotebookEntries(sessionId);
                state.statusText = resultsTab.investigationStatus(sessionId);
                state.payload = payload;
                states.add(state);
            }
            settings.setString(SETTINGS_INVESTIGATION_STATES_JSON, objectMapper.writeValueAsString(states));
            settings.setString(SETTINGS_ACTIVE_INVESTIGATION_ID, firstNonBlank(activeInvestigationId, resultsTab.activeInvestigationId()));
            settings.setBoolean(SETTINGS_REUSE_REPEATER_INVESTIGATIONS, resultsTab.reuseRepeaterInvestigations());
        } catch (Exception exception) {
            api.logging().logToError("Unable to persist AI Bridge investigations: " + rootCauseMessage(exception));
        }
    }

    private void cancelOperatorFollowUpAsync() {
        if (activeOperatorFollowUpFuture == null || activeOperatorFollowUpFuture.isDone()) {
            resultsTab.showFollowUpCanceled("No operator-console AI follow-up is currently running.");
            return;
        }

        cancelActiveOperatorFollowUp(true);
    }

    private void cancelActiveOperatorFollowUp(boolean notifyUi) {
        activeOperatorFollowUpToken = followUpTokenSequence.incrementAndGet();
        if (activeOperatorFollowUpFuture != null) {
            activeOperatorFollowUpFuture.cancel(true);
            activeOperatorFollowUpFuture = null;
        }
        String canceledSessionId = activeOperatorFollowUpSessionId;
        activeOperatorFollowUpSessionId = "";
        if (!canceledSessionId.isBlank()) {
            resultsTab.showInvestigationFollowUpCanceled(
                    canceledSessionId,
                    notifyUi
                            ? "AI follow-up stopped locally for this investigation. You can submit another question now."
                            : ""
            );
        }
        if (notifyUi) {
            resultsTab.showFollowUpCanceled("AI follow-up stopped locally. You can edit the request and submit again.");
            api.logging().logToOutput("AI Bridge follow-up was canceled locally.");
        }
    }

    private void cancelInvestigationFollowUp(String sessionId, boolean notifyUi) {
        if (sessionId == null || sessionId.isBlank()) {
            return;
        }
        activeInvestigationFollowUpTokens.remove(sessionId);
        CompletableFuture<AdvisoryResponse> activeFuture = activeInvestigationFollowUps.remove(sessionId);
        if (activeFuture != null) {
            activeFuture.cancel(true);
        }
        if (notifyUi) {
            resultsTab.showInvestigationError(sessionId, "The AI follow-up was stopped locally for this investigation.");
            api.logging().logToOutput("AI Bridge investigation follow-up was canceled locally for " + sessionId + ".");
        }
    }

    private void refreshToolInventoryAsync() {
        refreshToolInventoryAsync(true);
    }

    private void refreshToolInventoryAfterBackendReadyAsync() {
        resultsTab.showBackendHealthChecking("Checking backend health before the first inventory refresh.");
        resultsTab.showToolInventoryDeferred("Waiting for the local AI Bridge backend before the first Kali WSL inventory refresh.");
        checkBackendHealthThenRefreshToolInventory(STARTUP_HEALTHCHECK_ATTEMPTS);
    }

    private void checkBackendHealthThenRefreshToolInventory(int attemptsRemaining) {
        bridgeClient.checkRuntimeHealthAsync(resultsTab.endpointUrl())
                .whenComplete((healthy, error) -> {
                    StartupHealthGate.Decision decision = StartupHealthGate.decision(Boolean.TRUE.equals(healthy), attemptsRemaining);
                    if (decision.refreshInventory()) {
                        resultsTab.showBackendHealthy(decision.backendHealthText());
                        refreshToolInventoryAsync();
                        return;
                    }
                    if (decision.retry()) {
                        resultsTab.showBackendHealthDeferred(decision.backendHealthText());
                        CompletableFuture.delayedExecutor(STARTUP_HEALTHCHECK_DELAY_MILLIS, TimeUnit.MILLISECONDS)
                                .execute(() -> checkBackendHealthThenRefreshToolInventory(attemptsRemaining - 1));
                        return;
                    }
                    resultsTab.showBackendUnhealthy(decision.backendHealthText());
                    resultsTab.showToolInventoryDeferred(decision.toolInventoryText());
                    api.logging().logToOutput("AI Bridge deferred the automatic tool inventory refresh until the backend becomes healthy.");
                });
    }

    private void refreshToolInventoryAsync(boolean retryOnTransientFailure) {
        resultsTab.showToolInventoryLoading();
        bridgeClient.fetchToolInventoryAsync(resultsTab.endpointUrl(), true)
                .whenComplete((response, error) -> {
                    if (error != null) {
                        String message = rootCauseMessage(error);
                        if (retryOnTransientFailure && isTransientToolInventoryFailure(message)) {
                            api.logging().logToOutput("AI Bridge tool inventory hit a transient channel reset. Retrying once.");
                            refreshToolInventoryAsync(false);
                            return;
                        }
                        if (isTransientToolInventoryFailure(message)) {
                            api.logging().logToOutput("AI Bridge tool inventory refresh was interrupted by a transient local HTTP channel reset.");
                        } else {
                            api.logging().logToError("AI Bridge tool inventory failed: " + message);
                        }
                        resultsTab.showToolInventoryError(message);
                        return;
                    }

                    resultsTab.showToolInventory(response);
                    resultsTab.showBackendHealthy("Backend healthy. Tool inventory loaded.");
                    api.logging().logToOutput("AI Bridge tool inventory refreshed.");
                });
    }

    private boolean isTransientToolInventoryFailure(String message) {
        String normalized = firstNonBlank(message, "").toLowerCase();
        return normalized.contains("closedchannelexception")
                || normalized.contains("closed channel")
                || normalized.contains("channel reset");
    }

    private void launchBurpScanAsync(ScanLaunchRequest request) {
        CompletableFuture.runAsync(() -> {
            String targetUrl = firstNonBlank(request.getTargetUrl(), "");
            if (targetUrl.isBlank()) {
                throw new IllegalArgumentException("The scan target URL is blank.");
            }

            String scanType = firstNonBlank(request.getScanType(), "Audit only");
            String auditConfigLabel = firstNonBlank(request.getAuditConfiguration(), "Active audit checks");
            BuiltInAuditConfiguration auditConfiguration = "Passive audit checks".equalsIgnoreCase(auditConfigLabel)
                    ? BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                    : BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS;

            StringBuilder status = new StringBuilder();
            status.append("AI Bridge launched Burp tasks for ").append(targetUrl).append(".");
            List<String> selectedBchecks = request.getSelectedBchecks();
            BcheckImportSummary importSummary = importSelectedBchecks(selectedBchecks);

            if ("Crawl only".equalsIgnoreCase(scanType) || "Crawl and audit".equalsIgnoreCase(scanType)) {
                activeCrawlTask = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(targetUrl));
                status.append(" Crawl status: ").append(safeTaskStatusMessage(activeCrawlTask)).append(".");
            }

            if ("Audit only".equalsIgnoreCase(scanType) || "Crawl and audit".equalsIgnoreCase(scanType)) {
                activeAuditTask = api.scanner().startAudit(AuditConfiguration.auditConfiguration(auditConfiguration));
                activeAuditTask.addRequest(HttpRequest.httpRequestFromUrl(targetUrl));
                status.append(" Audit status: ").append(safeTaskStatusMessage(activeAuditTask)).append(".");
            }

            if ("Crawl and audit".equalsIgnoreCase(scanType)) {
                status.append(" Note: Montoya starts crawl and audit as separate tasks; it does not expose the native combined New Scan workflow, saved configs, or resource pool selection.");
            } else {
                status.append(" Note: Burp resource pools and full New Scan wizard settings are not exposed by Montoya.");
            }

            if (!selectedBchecks.isEmpty()) {
                status.append(" Selected BChecks: ").append(String.join("; ", selectedBchecks)).append(".");
            }
            if (!importSummary.imported().isEmpty()) {
                status.append(" Imported into Burp before launch: ").append(String.join("; ", importSummary.imported())).append(".");
            } else if (!selectedBchecks.isEmpty()) {
                status.append(" No selected BChecks were imported, so Burp will only use checks already present in your Burp configuration.");
            }
            if (!importSummary.failed().isEmpty()) {
                status.append(" Import failures: ").append(String.join("; ", importSummary.failed())).append(".");
            }

            api.logging().logToOutput("AI Bridge launched Burp scan setup: " + scanType + " for " + targetUrl);
            resultsTab.showScanLaunchStatus(status.toString());
            refreshScanBridgeState("Burp scan launched from AI Bridge for " + targetUrl + ".");
        }).exceptionally(error -> {
            String message = rootCauseMessage(error);
            api.logging().logToError("AI Bridge scan launch failed: " + message);
            resultsTab.showScanLaunchStatus("Unable to start Burp scan: " + message);
            return null;
        });
    }

    private void applyBurpSettingsAsync() {
        resultsTab.showBurpSettingsSyncStarting("Applying AI Bridge-managed Burp scope and custom headers...");
        CompletableFuture.runAsync(() -> {
            ParsedUrlLines includeUrls = parseScopeUrls(resultsTab.scopeIncludesText());
            ParsedUrlLines excludeUrls = parseScopeUrls(resultsTab.scopeExcludesText());
            ParsedHeaderRules headerRules = parseHeaderRules(resultsTab.customHeadersText());

            if (includeUrls.urls().isEmpty() && excludeUrls.urls().isEmpty() && headerRules.headers().isEmpty()) {
                throw new IllegalArgumentException(
                        "Nothing to apply yet. Add in-scope URLs, out-of-scope URLs, or custom headers in Program Context first."
                );
            }

            List<String> applied = new ArrayList<>();
            List<String> skipped = new ArrayList<>();
            synchronized (burpSettingsLock) {
                restoreTrackedScopeState(skipped);
                clearHeaderAutomation();

                LinkedHashMap<String, Boolean> nextScopeState = new LinkedHashMap<>();
                for (String url : includeUrls.urls()) {
                    boolean wasInScope = api.scope().isInScope(url);
                    nextScopeState.put(url, wasInScope);
                    api.scope().includeInScope(url);
                }
                for (String url : excludeUrls.urls()) {
                    boolean wasInScope = api.scope().isInScope(url);
                    nextScopeState.put(url, wasInScope);
                    api.scope().excludeFromScope(url);
                }
                appliedScopeState = nextScopeState;
                activeScopeIncludePrefixes = normalizedScopeMatchers(includeUrls.urls());
                activeScopeExcludePrefixes = normalizedScopeMatchers(excludeUrls.urls());
                activeBurpHeaderRules = new LinkedHashMap<>(headerRules.headers());
                if (!activeBurpHeaderRules.isEmpty()) {
                    burpHeaderAutomationRegistration = api.http().registerHttpHandler(buildBurpHeaderAutomationHandler());
                }
            }

            if (!includeUrls.urls().isEmpty()) {
                applied.add(includeUrls.urls().size() + " in-scope URL(s)");
            }
            if (!excludeUrls.urls().isEmpty()) {
                applied.add(excludeUrls.urls().size() + " out-of-scope URL(s)");
            }
            if (!headerRules.headers().isEmpty()) {
                applied.add(headerRules.headers().size() + " custom header rule(s)");
            }
            if (!includeUrls.invalidLines().isEmpty()) {
                skipped.add(includeUrls.invalidLines().size() + " invalid in-scope line(s)");
            }
            if (!excludeUrls.invalidLines().isEmpty()) {
                skipped.add(excludeUrls.invalidLines().size() + " invalid out-of-scope line(s)");
            }
            if (!headerRules.invalidLines().isEmpty()) {
                skipped.add(headerRules.invalidLines().size() + " invalid header line(s)");
            }

            StringBuilder status = new StringBuilder("Applied to Burp: ");
            status.append(String.join(", ", applied)).append(".");
            if (!headerRules.headers().isEmpty()) {
                status.append(" Header injection is now active for matching in-scope requests handled by Burp.");
            }
            if (!skipped.isEmpty()) {
                status.append(" Skipped: ").append(String.join(", ", skipped)).append(".");
            }
            status.append(" Other Burp settings from the advisory remain recommendation-only.");

            api.logging().logToOutput("AI Bridge synced supported Burp settings: " + status);
            resultsTab.showBurpSettingsSyncStatus(status.toString(), hasManagedBurpSettings());
        }).exceptionally(error -> {
            String message = rootCauseMessage(error);
            api.logging().logToError("AI Bridge Burp settings sync failed: " + message);
            resultsTab.showBurpSettingsSyncStatus("Unable to apply Burp scope/header rules: " + message, hasManagedBurpSettings());
            return null;
        });
    }

    private void disableBurpSettingsAutomationAsync() {
        resultsTab.showBurpSettingsSyncStarting("Restoring AI Bridge-managed Burp scope and header rules...");
        CompletableFuture.runAsync(() -> {
            List<String> restoreErrors = new ArrayList<>();
            boolean hadManagedSettings;
            synchronized (burpSettingsLock) {
                hadManagedSettings = hasManagedBurpSettingsLocked();
                restoreTrackedScopeState(restoreErrors);
                clearHeaderAutomation();
                activeScopeIncludePrefixes = List.of();
                activeScopeExcludePrefixes = List.of();
                activeBurpHeaderRules = Map.of();
            }

            String message;
            if (!hadManagedSettings) {
                message = "No AI Bridge-managed Burp scope or header rules are active right now.";
            } else if (restoreErrors.isEmpty()) {
                message = "AI Bridge-managed Burp scope/header sync is disabled. Any URLs touched by AI Bridge were restored to their earlier in-scope state.";
            } else {
                message = "AI Bridge-managed header rules were disabled, but some scope entries could not be restored: "
                        + String.join("; ", restoreErrors);
            }
            api.logging().logToOutput("AI Bridge Burp settings sync disabled.");
            resultsTab.showBurpSettingsSyncStatus(message, false);
        }).exceptionally(error -> {
            String message = rootCauseMessage(error);
            api.logging().logToError("AI Bridge Burp settings disable failed: " + message);
            resultsTab.showBurpSettingsSyncStatus("Unable to disable AI Bridge-managed Burp rules: " + message, hasManagedBurpSettings());
            return null;
        });
    }

    private void saveAiBridgeProjectSettings() {
        try {
            PersistedObject settings = currentProjectSettingsObject(true);
            if (settings == null) {
                throw new IllegalStateException("Burp project settings storage is unavailable.");
            }
            settings.setString(SETTINGS_BURP_CONFIG_EXPORT, resultsTab.burpConfigExportText());
            settings.setString(SETTINGS_BURP_SCREENSHOT_AUDIT, resultsTab.burpScreenshotAuditText());
            settings.setString(SETTINGS_LOADED_BURP_TOOLS, resultsTab.savedBurpToolsText());
            settings.setString(SETTINGS_PROGRAM_POLICY, resultsTab.savedProgramPolicyText());
            settings.setString(SETTINGS_PROGRAM_SCREENSHOT_AUDIT, resultsTab.savedProgramScreenshotText());
            settings.setBoolean(SETTINGS_AUTO_USE, resultsTab.autoUseSavedSettings());
            resultsTab.showAiBridgeSettingsStatus("Saved AI-Bridge settings for " + currentProjectLabel() + ".");
            api.logging().logToOutput("AI Bridge project settings saved for " + currentProjectLabel() + ".");
        } catch (Exception exception) {
            String message = rootCauseMessage(exception);
            resultsTab.showAiBridgeSettingsStatus("Unable to save AI-Bridge project settings: " + message);
            api.logging().logToError("AI Bridge settings save failed: " + message);
        }
    }

    private void reloadAiBridgeProjectSettings() {
        try {
            AiBridgeProjectSettings settings = readCurrentProjectSettings();
            resultsTab.showAiBridgeSettingsProject(currentProjectLabel());
            resultsTab.applyPersistedAiBridgeSettings(
                    settings.burpConfigExportText(),
                    settings.burpScreenshotAuditText(),
                    settings.loadedBurpToolsText(),
                    settings.programPolicyText(),
                    settings.programScreenshotAuditText(),
                    settings.autoUseSavedSettings(),
                    "Loaded AI-Bridge settings for " + currentProjectLabel() + "."
            );
            api.logging().logToOutput("AI Bridge project settings loaded for " + currentProjectLabel() + ".");
        } catch (Exception exception) {
            String message = rootCauseMessage(exception);
            resultsTab.showAiBridgeSettingsStatus("Unable to load AI-Bridge project settings: " + message);
            api.logging().logToError("AI Bridge settings load failed: " + message);
        }
    }

    private void clearAiBridgeProjectSettings() {
        try {
            PersistedObject root = projectSettingsRoot(false);
            if (root != null) {
                root.deleteChildObject(currentProjectStorageKey());
            }
            resultsTab.applyPersistedAiBridgeSettings("", "", "", "", "", true, "Cleared saved AI-Bridge settings for " + currentProjectLabel() + ".");
            resultsTab.showVisionReviewStatus("No screenshot vision review has run yet.");
            api.logging().logToOutput("AI Bridge project settings cleared for " + currentProjectLabel() + ".");
        } catch (Exception exception) {
            String message = rootCauseMessage(exception);
            resultsTab.showAiBridgeSettingsStatus("Unable to clear AI-Bridge project settings: " + message);
            api.logging().logToError("AI Bridge settings clear failed: " + message);
        }
    }

    private AiBridgeProjectSettings readCurrentProjectSettings() {
        PersistedObject settings = currentProjectSettingsObject(false);
        if (settings == null) {
            return AiBridgeProjectSettings.empty();
        }
        Boolean autoUse = settings.getBoolean(SETTINGS_AUTO_USE);
        return new AiBridgeProjectSettings(
                firstNonBlank(settings.getString(SETTINGS_BURP_CONFIG_EXPORT), ""),
                firstNonBlank(settings.getString(SETTINGS_BURP_SCREENSHOT_AUDIT), ""),
                firstNonBlank(settings.getString(SETTINGS_LOADED_BURP_TOOLS), ""),
                firstNonBlank(settings.getString(SETTINGS_PROGRAM_POLICY), ""),
                firstNonBlank(settings.getString(SETTINGS_PROGRAM_SCREENSHOT_AUDIT), ""),
                autoUse == null || autoUse
        );
    }

    private PersistedObject projectSettingsRoot(boolean createIfMissing) {
        PersistedObject extensionData = api.persistence().extensionData();
        PersistedObject root = extensionData.getChildObject(PROJECT_SETTINGS_ROOT_KEY);
        if (root == null && createIfMissing) {
            root = PersistedObject.persistedObject();
            extensionData.setChildObject(PROJECT_SETTINGS_ROOT_KEY, root);
        }
        return root;
    }

    private PersistedObject currentProjectSettingsObject(boolean createIfMissing) {
        PersistedObject root = projectSettingsRoot(createIfMissing);
        if (root == null) {
            return null;
        }
        String projectKey = currentProjectStorageKey();
        PersistedObject child = root.getChildObject(projectKey);
        if (child == null && createIfMissing) {
            child = PersistedObject.persistedObject();
            root.setChildObject(projectKey, child);
        }
        return child;
    }

    private String currentProjectStorageKey() {
        String id = firstNonBlank(api.project().id(), "").trim();
        return id.isBlank() ? "default-project" : id;
    }

    private String currentProjectLabel() {
        String name = firstNonBlank(api.project().name(), "").trim();
        String id = firstNonBlank(api.project().id(), "").trim();
        if (name.isBlank() && id.isBlank()) {
            return "Unknown Burp project";
        }
        if (name.isBlank()) {
            return id;
        }
        if (id.isBlank()) {
            return name;
        }
        return name + " (" + id + ")";
    }

    private void initializeCollaboratorClient() {
        try {
            ensureCollaboratorClient(false);
            resultsTab.showCollaboratorClientState(
                    latestCollaboratorPayload,
                    "AI Bridge Collaborator client ready. Use the payload in manual tests, then click Sync Client."
            );
        } catch (Exception exception) {
            String message = rootCauseMessage(exception);
            api.logging().logToError("AI Bridge Collaborator initialization failed: " + message);
            resultsTab.showCollaboratorSyncError(message);
        }
    }

    private void syncCollaboratorClientAsync() {
        resultsTab.showCollaboratorSyncLoading();
        CompletableFuture.runAsync(() -> {
            ensureCollaboratorClient(false);
            List<Interaction> interactions = new ArrayList<>(collaboratorClient.getAllInteractions());
            interactions.sort(Comparator.comparing(Interaction::timeStamp).reversed());

            String autoEvidence = summarizeStandaloneCollaboratorInteractions(interactions);
            String manualNotes = stripManagedCollaboratorSyncSection(resultsTab.collaboratorEvidenceText());
            String mergedEvidence = mergeEvidence(autoEvidence, manualNotes, "Manual Collaborator notes");
            String status = interactions.isEmpty()
                    ? "Sync complete. No issue-unlinked AI Bridge Collaborator interactions have arrived yet."
                    : "Sync complete. Attached " + interactions.size() + " AI Bridge Collaborator interaction(s).";

            resultsTab.showCollaboratorSyncResult(mergedEvidence, latestCollaboratorPayload, status);
            api.logging().logToOutput("AI Bridge Collaborator sync completed with " + interactions.size() + " interaction(s).");
        }).exceptionally(error -> {
            String message = rootCauseMessage(error);
            api.logging().logToError("AI Bridge Collaborator sync failed: " + message);
            resultsTab.showCollaboratorSyncError(message);
            return null;
        });
    }

    private void rotateCollaboratorClientAsync() {
        resultsTab.showCollaboratorSyncLoading();
        CompletableFuture.runAsync(() -> {
            ensureCollaboratorClient(true);
            resultsTab.showCollaboratorClientState(
                    latestCollaboratorPayload,
                    "AI Bridge Collaborator client rotated. Use the new payload for fresh manual checks, then click Sync Client."
            );
            api.logging().logToOutput("AI Bridge Collaborator client rotated.");
        }).exceptionally(error -> {
            String message = rootCauseMessage(error);
            api.logging().logToError("AI Bridge Collaborator rotation failed: " + message);
            resultsTab.showCollaboratorSyncError(message);
            return null;
        });
    }

    private void analyzeRecentScanIssuesAsync() {
        List<AuditIssue> issues = recentScanIssuesSnapshot();
        if (issues.isEmpty()) {
            refreshScanBridgeState("No recent Burp scan issues are available for AI Bridge yet.");
            return;
        }
        analyzeAuditIssuesAsync(issues, ToolType.SCANNER, InvocationType.SCANNER_RESULTS);
        refreshScanBridgeState("Submitting " + issues.size() + " recent Burp scan issue(s) to AI Bridge manually.");
    }

    private void analyzeCurrentTargetScanIssuesAsync() {
        String targetUrl = firstNonBlank(resultsTab.scanTargetUrl(), "");
        if (targetUrl.isBlank() && latestSinglePayload != null) {
            targetUrl = firstNonBlank(latestSinglePayload.getTargetUrl(), "");
        }
        if (targetUrl.isBlank()) {
            refreshScanBridgeState("Type or load a target URL first, then analyze current-target scan findings.");
            return;
        }

        List<AuditIssue> issues = findIssuesForTarget(targetUrl);
        if (issues.isEmpty()) {
            refreshScanBridgeState("No Burp scan issues were found for the current target: " + targetUrl);
            return;
        }

        analyzeAuditIssuesAsync(issues, ToolType.SCANNER, InvocationType.SCANNER_RESULTS);
        refreshScanBridgeState("Submitting " + issues.size() + " current-target Burp scan issue(s) to AI Bridge manually.");
    }

    private void openBcheckCatalogAsync() {
        resultsTab.showBcheckCatalogLoading();
        bridgeClient.fetchBcheckCatalogAsync(resultsTab.endpointUrl())
                .whenComplete((entries, error) -> {
                    if (error != null) {
                        String message = rootCauseMessage(error);
                        api.logging().logToError("AI Bridge BCheck catalog failed: " + message);
                        resultsTab.showScanLaunchStatus("Unable to load the BCheck catalog: " + message);
                        return;
                    }

                    resultsTab.showBcheckCatalogChooser(entries);
                    api.logging().logToOutput("AI Bridge BCheck catalog loaded with " + entries.size() + " entries.");
                });
    }

    private void ensureCollaboratorClient(boolean rotate) {
        PersistedObject extensionData = api.persistence().extensionData();
        CollaboratorClient client = null;

        if (!rotate) {
            String persistedSecret = extensionData.getString(COLLABORATOR_SECRET_KEY);
            if (persistedSecret != null && !persistedSecret.isBlank()) {
                try {
                    client = api.collaborator().restoreClient(SecretKey.secretKey(persistedSecret));
                } catch (Exception exception) {
                    api.logging().logToError("Unable to restore persisted AI Bridge Collaborator client: " + rootCauseMessage(exception));
                }
            }
        }

        if (client == null) {
            client = api.collaborator().createClient();
        }

        collaboratorClient = client;
        extensionData.setString(COLLABORATOR_SECRET_KEY, collaboratorClient.getSecretKey().toString());
        latestCollaboratorPayload = collaboratorClient.generatePayload(COLLABORATOR_CUSTOM_DATA).toString();
    }

    private void submitFeedbackAsync(String label, String notes) {
        String endpointUrl = resultsTab.endpointUrl();
        String jobId = resultsTab.currentJobId();
        if (jobId == null || jobId.isBlank()) {
            resultsTab.showFeedbackError("No completed job ID is available for feedback.");
            return;
        }

        bridgeClient.submitFeedbackAsync(endpointUrl, jobId, label, notes)
                .whenComplete((ignored, error) -> {
                    if (error != null) {
                        String message = rootCauseMessage(error);
                        api.logging().logToError("AI Bridge feedback failed for job " + jobId + ": " + message);
                        resultsTab.showFeedbackError(message);
                        return;
                    }

                    api.logging().logToOutput("AI Bridge feedback recorded for job " + jobId + " as " + label + ".");
                    resultsTab.showFeedbackRecorded(label);
                });
    }

    private void refreshReasoningAsync(String jobId) {
        if (jobId == null || jobId.isBlank()) {
            resultsTab.showReasoningUnavailable("Stored reasoning data is unavailable because the current job id is blank.");
            return;
        }

        String endpointUrl = resultsTab.endpointUrl();
        resultsTab.showReasoningLoading(jobId);
        bridgeClient.fetchReasoningSummaryAsync(endpointUrl, jobId)
                .thenCombine(
                        bridgeClient.fetchPhaseHistoryAsync(endpointUrl, jobId, "", 6),
                        (reasoning, history) -> Map.entry(reasoning, history)
                )
                .whenComplete((bundle, error) -> {
                    if (error != null) {
                        String message = rootCauseMessage(error);
                        api.logging().logToError("AI Bridge reasoning refresh failed for job " + jobId + ": " + message);
                        if (jobId.equals(resultsTab.currentJobId())) {
                            resultsTab.showReasoningUnavailable(message);
                        }
                        return;
                    }
                    if (!jobId.equals(resultsTab.currentJobId())) {
                        return;
                    }
                    resultsTab.updateReasoningSummary(bundle.getKey(), bundle.getValue());
                });
    }

    private void recordScanIssue(AuditIssue issue) {
        synchronized (scanIssueLock) {
            recentScanIssues.removeIf(existing -> sameIssue(existing, issue));
            recentScanIssues.add(0, issue);
            if (recentScanIssues.size() > MAX_RECENT_SCAN_ISSUES) {
                recentScanIssues.remove(recentScanIssues.size() - 1);
            }
        }
        synchronized (autoScanLock) {
            pendingAutoScanIssues.removeIf(existing -> sameIssue(existing, issue));
            pendingAutoScanIssues.add(0, issue);
            if (pendingAutoScanIssues.size() > MAX_RECENT_SCAN_ISSUES) {
                pendingAutoScanIssues.remove(pendingAutoScanIssues.size() - 1);
            }
        }

        String target = firstNonBlank(issue.baseUrl(), "unknown-target");
        api.logging().logToOutput("AI Bridge observed Burp scan issue: " + firstNonBlank(issue.name(), "Unnamed issue") + " @ " + target);
        if (!AUTO_SCAN_TRIAGE_ENABLED) {
            synchronized (autoScanLock) {
                pendingAutoScanIssues.clear();
                if (scheduledAutoScanFlush != null) {
                    scheduledAutoScanFlush.cancel(false);
                    scheduledAutoScanFlush = null;
                }
            }
            latestAutoScanStatus = "Observed new Burp scan issue for " + target + ". Review it manually with 'Review Recent Findings' or 'Review This Target'.";
            latestAutoScanSummary = "Automatic scan triage is disabled. Use the manual review actions when you want AI Bridge to analyze scanner findings.";
            refreshScanBridgeState(latestAutoScanStatus);
            return;
        }

        latestAutoScanStatus = "Observed new Burp scan issue for " + target + ". AI Bridge background triage will run after the debounce window.";
        scheduleAutoScanFlush();
        refreshScanBridgeState(latestAutoScanStatus);
    }

    private void refreshScanBridgeState(String status) {
        List<AuditIssue> recentIssues = recentScanIssuesSnapshot();
        int pendingAutoIssues;
        boolean autoJobRunning;
        synchronized (autoScanLock) {
            pendingAutoIssues = pendingAutoScanIssues.size();
            autoJobRunning = activeAutoScanFuture != null && !activeAutoScanFuture.isDone();
        }
        boolean hasRecentIssues = !recentIssues.isEmpty();
        boolean hasTargetIssues = latestSinglePayload != null
                && latestSinglePayload.getTargetUrl() != null
                && !latestSinglePayload.getTargetUrl().isBlank()
                && !findIssuesForTarget(latestSinglePayload.getTargetUrl()).isEmpty();

        StringBuilder summary = new StringBuilder();
        summary.append("Recent Burp scan findings observed by AI Bridge:");
        if (recentIssues.isEmpty()) {
            summary.append(System.lineSeparator()).append("- No issues observed yet.");
        } else {
            int count = 0;
            for (AuditIssue issue : recentIssues) {
                if (count >= MAX_AUTO_ISSUES) {
                    break;
                }
                summary.append(System.lineSeparator()).append("- ")
                        .append(firstNonBlank(issue.name(), "Unnamed issue"))
                        .append(" | severity: ").append(issue.severity())
                        .append(" | confidence: ").append(issue.confidence());
                String baseUrl = firstNonBlank(issue.baseUrl(), "");
                if (!baseUrl.isBlank()) {
                    summary.append(" | url: ").append(baseUrl);
                }
                count++;
            }
            if (recentIssues.size() > MAX_AUTO_ISSUES) {
                summary.append(System.lineSeparator())
                        .append("- ... ").append(recentIssues.size() - MAX_AUTO_ISSUES).append(" more recent issue(s) tracked.");
            }
        }

        summary.append(System.lineSeparator()).append(System.lineSeparator())
                .append("Current target: ")
                .append(latestSinglePayload == null ? "none selected" : firstNonBlank(latestSinglePayload.getTargetUrl(), "unknown-target"))
                .append(System.lineSeparator())
                .append("Launcher tasks: crawl=")
                .append(activeCrawlTask == null ? "none" : safeTaskStatusMessage(activeCrawlTask))
                .append(" | audit=")
                .append(activeAuditTask == null ? "none" : safeTaskStatusMessage(activeAuditTask));

        if (AUTO_SCAN_TRIAGE_ENABLED) {
            summary.append(System.lineSeparator())
                    .append("Background triage queue: ")
                    .append(pendingAutoIssues)
                    .append(" pending")
                    .append(autoJobRunning ? ", 1 running" : ", idle");
        } else {
            summary.append(System.lineSeparator())
                    .append("Background triage: disabled (manual review only).");
        }

        summary.append(System.lineSeparator())
                .append("Workflow: send a selected Burp audit issue to AI Bridge, or use 'Review Recent Findings' or 'Review This Target' when you want AI Bridge to analyze scanner findings.");

        summary.append(System.lineSeparator()).append(System.lineSeparator())
                .append(latestAutoScanSummary);

        resultsTab.showScanBridgeState(summary.toString(), status, hasRecentIssues, hasTargetIssues);
    }

    private List<AuditIssue> recentScanIssuesSnapshot() {
        synchronized (scanIssueLock) {
            return new ArrayList<>(recentScanIssues);
        }
    }

    private void scheduleAutoScanFlush() {
        synchronized (autoScanLock) {
            if (scheduledAutoScanFlush != null) {
                scheduledAutoScanFlush.cancel(false);
            }
            scheduledAutoScanFlush = autoScanScheduler.schedule(this::flushAutoScanQueue, AUTO_SCAN_DEBOUNCE_MILLIS, TimeUnit.MILLISECONDS);
        }
    }

    private void flushAutoScanQueue() {
        List<AuditIssue> batch = new ArrayList<>();
        synchronized (autoScanLock) {
            if (activeAutoScanFuture != null && !activeAutoScanFuture.isDone()) {
                latestAutoScanStatus = "Background AI Bridge scan triage is waiting for the current auto-triage job to finish.";
                refreshScanBridgeState(latestAutoScanStatus);
                scheduleAutoScanFlush();
                return;
            }

            if (pendingAutoScanIssues.isEmpty()) {
                refreshScanBridgeState(latestAutoScanStatus);
                return;
            }

            while (!pendingAutoScanIssues.isEmpty() && batch.size() < MAX_AUTO_ISSUES) {
                batch.add(pendingAutoScanIssues.remove(0));
            }
            scheduledAutoScanFlush = null;
        }

        submitAutoScanIssuesAsync(batch);
    }

    private void submitAutoScanIssuesAsync(List<AuditIssue> issues) {
        if (issues.isEmpty()) {
            refreshScanBridgeState(latestAutoScanStatus);
            return;
        }

        AssessmentRequest payload = buildPayloadFromIssues(issues, ToolType.SCANNER, InvocationType.SCANNER_RESULTS);
        List<String> annotations = new ArrayList<>(payload.getAnnotations());
        if (!annotations.contains("scanner_auto_triage")) {
            annotations.add("scanner_auto_triage");
        }
        payload.setAnnotations(annotations);

        latestAutoScanStatus = "Submitting " + issues.size() + " new Burp scan issue(s) to AI Bridge in the background.";
        refreshScanBridgeState(latestAutoScanStatus);
        api.logging().logToOutput(
                "AI Bridge auto-triaging " + issues.size() + " Burp scan issue(s) for " + payload.getTargetUrl()
        );

        final String[] latestJobId = {""};
        CompletableFuture<AdvisoryResponse> future = bridgeClient.analyzeAsync(resultsTab.endpointUrl(), payload, status -> {
            latestJobId[0] = firstNonBlank(status.getJobId(), "");
            latestAutoScanStatus = "Background AI Bridge triage job " + latestJobId[0] + " is " + status.getStatus() + ".";
            refreshScanBridgeState(latestAutoScanStatus);
        });

        synchronized (autoScanLock) {
            activeAutoScanFuture = future;
        }

        future.whenComplete((response, error) -> {
            synchronized (autoScanLock) {
                activeAutoScanFuture = null;
            }

            if (error != null) {
                String message = rootCauseMessage(error);
                latestAutoScanStatus = "Background AI Bridge triage failed: " + message;
                latestAutoScanSummary = "Latest background AI Bridge triage failed for " + payload.getTargetUrl()
                        + System.lineSeparator()
                        + "- Error: " + message;
                api.logging().logToError("AI Bridge auto-triage failed for " + payload.getTargetUrl() + ": " + message);
            } else {
                latestAutoScanStatus = "Background AI Bridge triage completed for " + payload.getTargetUrl() + ".";
                latestAutoScanSummary = buildAutoScanSummary(payload, response, latestJobId[0]);
                api.logging().logToOutput("AI Bridge auto-triage completed for " + payload.getTargetUrl());
            }

            refreshScanBridgeState(latestAutoScanStatus);
            synchronized (autoScanLock) {
                if (!pendingAutoScanIssues.isEmpty()) {
                    scheduleAutoScanFlush();
                }
            }
        });
    }

    private String buildAutoScanSummary(AssessmentRequest payload, AdvisoryResponse response, String jobId) {
        StringBuilder builder = new StringBuilder();
        builder.append("Latest background AI Bridge triage:");
        builder.append(System.lineSeparator()).append("- Target: ").append(payload.getTargetUrl());
        if (jobId != null && !jobId.isBlank()) {
            builder.append(System.lineSeparator()).append("- Job ID: ").append(jobId);
        }
        builder.append(System.lineSeparator()).append("- Primary action: ")
                .append(firstNonBlank(response.getPrimaryNextAction(), "No primary action returned"));

        List<String> findings = response.getPotentialVulnerabilities();
        if (findings.isEmpty()) {
            builder.append(System.lineSeparator()).append("- Findings: none returned");
        } else {
            int count = 0;
            for (String finding : findings) {
                if (count >= 3) {
                    break;
                }
                builder.append(System.lineSeparator()).append("- Finding: ").append(compactSingleLine(finding, 180));
                count++;
            }
        }

        String analysis = compactSingleLine(response.getAnalysis(), 260);
        if (!analysis.isBlank()) {
            builder.append(System.lineSeparator()).append("- Analysis: ").append(analysis);
        }
        List<String> requestPlan = response.getRequestPlan();
        if (!requestPlan.isEmpty()) {
            builder.append(System.lineSeparator()).append("- Request plan:");
            int count = 0;
            for (String item : requestPlan) {
                if (count >= 3) {
                    break;
                }
                builder.append(System.lineSeparator()).append("  - ").append(compactSingleLine(item, 180));
                count++;
            }
        }
        List<String> bcheckRecommendations = response.getBcheckRecommendations();
        if (!bcheckRecommendations.isEmpty()) {
            builder.append(System.lineSeparator()).append("- Suggested BChecks to enable before confirmation:");
            int count = 0;
            for (String item : bcheckRecommendations) {
                if (count >= 2) {
                    break;
                }
                builder.append(System.lineSeparator()).append("  - ").append(compactSingleLine(item, 180));
                count++;
            }
        }
        List<String> manualTooling = response.getManualTooling();
        if (!manualTooling.isEmpty()) {
            builder.append(System.lineSeparator()).append("- Burp or external tooling to use next:");
            int count = 0;
            for (String item : manualTooling) {
                if (count >= 2) {
                    break;
                }
                builder.append(System.lineSeparator()).append("  - ").append(compactSingleLine(item, 180));
                count++;
            }
        }
        List<String> manualCommands = response.getManualCommands();
        if (!manualCommands.isEmpty()) {
            builder.append(System.lineSeparator()).append("- Concrete validation steps:");
            int count = 0;
            for (String item : manualCommands) {
                if (count >= 2) {
                    break;
                }
                builder.append(System.lineSeparator()).append("  - ").append(compactSingleLine(item, 180));
                count++;
            }
        }
        return builder.toString();
    }

    private BcheckImportSummary importSelectedBchecks(List<String> selectedBchecks) {
        if (selectedBchecks == null || selectedBchecks.isEmpty()) {
            return new BcheckImportSummary(List.of(), List.of());
        }

        List<String> imported = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        List<String> seenPaths = new ArrayList<>();
        for (String selection : selectedBchecks) {
            String relativePath = extractBcheckRelativePath(selection);
            if (relativePath.isBlank() || seenPaths.contains(relativePath)) {
                if (relativePath.isBlank()) {
                    failed.add("missing .bcheck path in: " + compactSingleLine(selection, 120));
                }
                continue;
            }
            seenPaths.add(relativePath);
            try {
                BCheckContentResponse response = bridgeClient.fetchBcheckContent(resultsTab.endpointUrl(), relativePath);
                if (response.getContent().isBlank()) {
                    api.logging().logToError("AI Bridge BCheck content was empty for " + relativePath);
                    failed.add(relativePath + " returned empty content");
                    continue;
                }
                BCheckImportResult result = api.scanner().bChecks().importBCheck(response.getContent());
                if (result != null && String.valueOf(result.status()).toLowerCase().contains("success")) {
                    imported.add(firstNonBlank(response.getRelativePath(), relativePath));
                } else {
                    String importErrors = result == null ? "unknown import result" : String.join("; ", result.importErrors());
                    api.logging().logToError("AI Bridge failed to import BCheck " + relativePath + ": " + importErrors);
                    failed.add(relativePath + " -> " + importErrors);
                }
            } catch (Exception exception) {
                String message = rootCauseMessage(exception);
                api.logging().logToError("AI Bridge failed to import selected BCheck " + relativePath + ": " + message);
                failed.add(relativePath + " -> " + message);
            }
        }
        return new BcheckImportSummary(List.copyOf(imported), List.copyOf(failed));
    }

    private String extractBcheckRelativePath(String selection) {
        if (selection == null || selection.isBlank()) {
            return "";
        }
        Matcher matcher = Pattern.compile("([A-Za-z0-9_ ./()-]+\\.bcheck)", Pattern.CASE_INSENSITIVE).matcher(selection);
        while (matcher.find()) {
            String candidate = matcher.group(1).trim().replace("\\", "/");
            if (candidate.toLowerCase().contains(".bcheck")) {
                return candidate;
            }
        }
        return "";
    }

    private HttpHandler buildBurpHeaderAutomationHandler() {
        return new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                if (!shouldApplyManagedHeaders(request)) {
                    return RequestToBeSentAction.continueWith(request);
                }

                HttpRequest updated = request;
                Map<String, String> headersSnapshot;
                synchronized (burpSettingsLock) {
                    headersSnapshot = new LinkedHashMap<>(activeBurpHeaderRules);
                }
                for (Map.Entry<String, String> entry : headersSnapshot.entrySet()) {
                    updated = updated.hasHeader(entry.getKey())
                            ? updated.withUpdatedHeader(entry.getKey(), entry.getValue())
                            : updated.withAddedHeader(entry.getKey(), entry.getValue());
                }
                return RequestToBeSentAction.continueWith(updated);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                return ResponseReceivedAction.continueWith(response);
            }
        };
    }

    private boolean shouldApplyManagedHeaders(HttpRequestToBeSent request) {
        String url = firstNonBlank(request.url(), "");
        if (url.isBlank()) {
            return false;
        }

        Map<String, String> headersSnapshot;
        List<String> includePrefixes;
        List<String> excludePrefixes;
        synchronized (burpSettingsLock) {
            headersSnapshot = activeBurpHeaderRules;
            includePrefixes = activeScopeIncludePrefixes;
            excludePrefixes = activeScopeExcludePrefixes;
        }
        if (headersSnapshot.isEmpty()) {
            return false;
        }
        if (matchesAnyPrefix(url, excludePrefixes)) {
            return false;
        }
        if (!includePrefixes.isEmpty()) {
            return matchesAnyPrefix(url, includePrefixes);
        }
        return request.isInScope();
    }

    private void clearHeaderAutomation() {
        if (burpHeaderAutomationRegistration != null) {
            try {
                burpHeaderAutomationRegistration.deregister();
            } catch (Exception exception) {
                api.logging().logToError("AI Bridge could not deregister managed Burp header automation: " + rootCauseMessage(exception));
            }
            burpHeaderAutomationRegistration = null;
        }
    }

    private void restoreTrackedScopeState(List<String> restoreErrors) {
        for (Map.Entry<String, Boolean> entry : appliedScopeState.entrySet()) {
            try {
                if (Boolean.TRUE.equals(entry.getValue())) {
                    api.scope().includeInScope(entry.getKey());
                } else {
                    api.scope().excludeFromScope(entry.getKey());
                }
            } catch (Exception exception) {
                restoreErrors.add(entry.getKey() + " -> " + rootCauseMessage(exception));
            }
        }
        appliedScopeState = Map.of();
    }

    private boolean hasManagedBurpSettings() {
        synchronized (burpSettingsLock) {
            return hasManagedBurpSettingsLocked();
        }
    }

    private boolean hasManagedBurpSettingsLocked() {
        return !appliedScopeState.isEmpty()
                || (burpHeaderAutomationRegistration != null && burpHeaderAutomationRegistration.isRegistered())
                || !activeBurpHeaderRules.isEmpty();
    }

    private ParsedUrlLines parseScopeUrls(String raw) {
        List<String> urls = new ArrayList<>();
        List<String> invalidLines = new ArrayList<>();
        if (raw == null || raw.isBlank()) {
            return new ParsedUrlLines(List.of(), List.of());
        }
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (String line : raw.split("\\R")) {
            String trimmed = sanitizeListLine(line);
            if (trimmed.isBlank()) {
                continue;
            }
            Matcher matcher = URL_PATTERN.matcher(trimmed);
            if (!matcher.find()) {
                invalidLines.add(trimmed);
                continue;
            }
            String url = trimTrailingPunctuation(matcher.group(1));
            if (!url.isBlank() && seen.add(url)) {
                urls.add(url);
            }
        }
        return new ParsedUrlLines(List.copyOf(urls), List.copyOf(invalidLines));
    }

    private ParsedHeaderRules parseHeaderRules(String raw) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        List<String> invalidLines = new ArrayList<>();
        if (raw == null || raw.isBlank()) {
            return new ParsedHeaderRules(Map.of(), List.of());
        }
        for (String line : raw.split("\\R")) {
            String trimmed = sanitizeListLine(line);
            if (trimmed.isBlank()) {
                continue;
            }
            int colon = trimmed.indexOf(':');
            if (colon <= 0 || colon == trimmed.length() - 1) {
                invalidLines.add(trimmed);
                continue;
            }
            String name = trimmed.substring(0, colon).trim();
            String value = trimmed.substring(colon + 1).trim();
            if (value.isBlank() || !HEADER_NAME_PATTERN.matcher(name).matches()) {
                invalidLines.add(trimmed);
                continue;
            }
            headers.put(name, value);
        }
        return new ParsedHeaderRules(Map.copyOf(headers), List.copyOf(invalidLines));
    }

    private List<String> normalizedScopeMatchers(List<String> urls) {
        if (urls == null || urls.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> matchers = new LinkedHashSet<>();
        for (String url : urls) {
            String normalized = normalizedTargetPrefix(url);
            if (!normalized.isBlank()) {
                matchers.add(normalized);
                continue;
            }
            String serviceRoot = normalizedServiceRoot(url);
            if (!serviceRoot.isBlank()) {
                matchers.add(serviceRoot);
            }
        }
        return List.copyOf(matchers);
    }

    private boolean matchesAnyPrefix(String url, List<String> prefixes) {
        if (url == null || url.isBlank() || prefixes == null || prefixes.isEmpty()) {
            return false;
        }
        for (String prefix : prefixes) {
            if (prefix != null && !prefix.isBlank() && url.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private String sanitizeListLine(String line) {
        String value = firstNonBlank(line, "").trim();
        if (value.startsWith("- ") || value.startsWith("* ")) {
            return value.substring(2).trim();
        }
        if (value.startsWith("• ")) {
            return value.substring(2).trim();
        }
        return value;
    }

    private String trimTrailingPunctuation(String value) {
        String result = firstNonBlank(value, "").trim();
        while (!result.isBlank()) {
            char last = result.charAt(result.length() - 1);
            if (last == '.' || last == ',' || last == ')' || last == ';') {
                result = result.substring(0, result.length() - 1).trim();
                continue;
            }
            break;
        }
        return result;
    }

    private String safeTaskStatusMessage(Object task) {
        if (task == null) {
            return "none";
        }
        try {
            return switch (task) {
                case Crawl crawl -> firstNonBlank(crawl.statusMessage(), "started");
                case Audit audit -> firstNonBlank(audit.statusMessage(), "started");
                default -> "started";
            };
        } catch (Exception exception) {
            String message = rootCauseMessage(exception);
            if (message.toLowerCase().contains("not yet implemented")) {
                return "started";
            }
            return "status unavailable";
        }
    }

    private record BcheckImportSummary(List<String> imported, List<String> failed) {
    }

    private record AiBridgeProjectSettings(
            String burpConfigExportText,
            String burpScreenshotAuditText,
            String loadedBurpToolsText,
            String programPolicyText,
            String programScreenshotAuditText,
            boolean autoUseSavedSettings
    ) {
        private static AiBridgeProjectSettings empty() {
            return new AiBridgeProjectSettings("", "", "", "", "", true);
        }
    }

    private boolean sameIssue(AuditIssue left, AuditIssue right) {
        return firstNonBlank(left.name(), "").equals(firstNonBlank(right.name(), ""))
                && firstNonBlank(left.baseUrl(), "").equals(firstNonBlank(right.baseUrl(), ""))
                && String.valueOf(left.severity()).equals(String.valueOf(right.severity()))
                && String.valueOf(left.confidence()).equals(String.valueOf(right.confidence()));
    }

    private void seedSelectedScannerContext(AssessmentRequest payload, List<AuditIssue> issues) {
        if (payload == null || issues == null || issues.isEmpty()) {
            return;
        }
        AuditIssue anchorIssue = issues.get(0);
        payload.setBurpDashboardIssue(buildIssueContext(anchorIssue, true));
        payload.setBurpRelatedScannerIssues(buildIssueContextList(filterSiblingIssues(anchorIssue, issues), false));
        payload.setRepeaterRequests(buildScannerRequestContexts(anchorIssue));
        payload.setProjectConfigSnapshot(buildProjectConfigSnapshot());
    }

    private Map<String, Object> buildIssueContext(AuditIssue issue, boolean includeScannerRequests) {
        Map<String, Object> issueContext = new LinkedHashMap<>();
        if (issue == null) {
            return issueContext;
        }

        String issueName = firstNonBlank(issue.name(), "");
        String detail = compactSingleLine(htmlToPlainText(firstNonBlank(issue.detail(), "")), 800);
        String baseUrl = firstNonBlank(issue.baseUrl(), "");
        String highlight = issueHighlightExcerpt(issue);

        issueContext.put("issue_id", "");
        issueContext.put("name", issueName);
        issueContext.put("severity", String.valueOf(issue.severity()));
        issueContext.put("confidence", String.valueOf(issue.confidence()));
        issueContext.put("detail", detail);
        issueContext.put("remediation", compactSingleLine(htmlToPlainText(firstNonBlank(issue.remediation(), "")), 400));
        issueContext.put("url", baseUrl);
        issueContext.put("affected_urls", baseUrl.isBlank() ? List.of() : List.of(baseUrl));
        issueContext.put("vuln_hint", issueFamily(issue));

        List<String> evidenceItems = new ArrayList<>();
        if (!highlight.isBlank()) {
            evidenceItems.add("Highlighted excerpt: " + highlight);
        }
        if (!detail.isBlank()) {
            evidenceItems.add("Scanner detail: " + compactSingleLine(detail, 280));
        }
        issueContext.put("evidence", evidenceItems);

        List<Map<String, Object>> highlights = new ArrayList<>();
        if (!highlight.isBlank()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("text", highlight);
            entry.put("label", "scanner-highlight");
            entry.put("reason", "Likely Burp-highlighted excerpt for this finding.");
            entry.put("part", "response");
            highlights.add(entry);
        }
        issueContext.put("highlights", highlights);
        issueContext.put("scanner_requests", includeScannerRequests ? buildScannerRequestContexts(issue) : List.of());
        return issueContext;
    }

    private List<Map<String, Object>> buildIssueContextList(List<AuditIssue> issues, boolean includeScannerRequests) {
        List<Map<String, Object>> contexts = new ArrayList<>();
        if (issues == null) {
            return contexts;
        }
        for (AuditIssue issue : issues) {
            Map<String, Object> context = buildIssueContext(issue, includeScannerRequests);
            if (!context.isEmpty()) {
                contexts.add(context);
            }
        }
        return contexts;
    }

    private List<AuditIssue> filterSiblingIssues(AuditIssue anchorIssue, List<AuditIssue> candidates) {
        if (anchorIssue == null || candidates == null || candidates.isEmpty()) {
            return List.of();
        }

        String anchorFamily = issueFamily(anchorIssue);
        String anchorPath = normalizedTargetPrefix(firstNonBlank(anchorIssue.baseUrl(), ""));
        List<AuditIssue> sameFamily = new ArrayList<>();
        List<AuditIssue> samePathGeneric = new ArrayList<>();
        List<AuditIssue> samePathFallback = new ArrayList<>();

        for (AuditIssue candidate : candidates) {
            if (candidate == null || sameIssue(anchorIssue, candidate)) {
                continue;
            }
            String candidatePath = normalizedTargetPrefix(firstNonBlank(candidate.baseUrl(), ""));
            if (!anchorPath.isBlank() && !anchorPath.equals(candidatePath)) {
                continue;
            }
            String candidateFamily = issueFamily(candidate);
            if (!anchorFamily.equals("general") && anchorFamily.equals(candidateFamily)) {
                sameFamily.add(candidate);
            } else if ("general".equals(candidateFamily)) {
                samePathGeneric.add(candidate);
            } else {
                samePathFallback.add(candidate);
            }
        }

        List<AuditIssue> ordered = new ArrayList<>();
        ordered.addAll(sameFamily);
        ordered.addAll(samePathGeneric);
        if (ordered.isEmpty()) {
            ordered.addAll(samePathFallback);
        }
        if (ordered.size() > MAX_AUTO_ISSUES) {
            return new ArrayList<>(ordered.subList(0, MAX_AUTO_ISSUES));
        }
        return ordered;
    }

    private String issueFamily(AuditIssue issue) {
        if (issue == null) {
            return "general";
        }
        return issueFamilyFromText(firstNonBlank(issue.name(), "") + " " + htmlToPlainText(firstNonBlank(issue.detail(), "")));
    }

    private String issueFamilyFromContext(Map<String, Object> issueContext) {
        if (issueContext == null || issueContext.isEmpty()) {
            return "general";
        }
        String explicitHint = firstNonBlank(String.valueOf(issueContext.getOrDefault("vuln_hint", "")), "").trim().toLowerCase(Locale.ROOT);
        if (!explicitHint.isBlank()) {
            return explicitHint;
        }
        return issueFamilyFromText(
                String.valueOf(issueContext.getOrDefault("name", "")) + " "
                        + String.valueOf(issueContext.getOrDefault("detail", ""))
        );
    }

    private String issueFamilyFromText(String text) {
        String value = firstNonBlank(text, "").toLowerCase(Locale.ROOT);
        if (value.contains("cross-site scripting") || value.contains(" xss")) {
            return "xss";
        }
        if (value.contains("direct object reference") || value.contains("access control") || value.contains("idor")) {
            return "authorization";
        }
        if (value.contains("server-side request forgery") || value.contains("ssrf")) {
            return "ssrf";
        }
        if (value.contains("sql injection") || value.contains(" sqli") || value.contains("injection")) {
            return "injection";
        }
        if (value.contains("authentication") || value.contains("session")) {
            return "authentication";
        }
        return "general";
    }

    private List<Map<String, Object>> buildScannerRequestContexts(AuditIssue issue) {
        if (issue == null || issue.requestResponses().isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> entries = new ArrayList<>();
        int count = 0;
        for (HttpRequestResponse requestResponse : issue.requestResponses()) {
            if (requestResponse == null || count >= 4) {
                break;
            }
            entries.add(buildRequestContextEntry(
                    requestResponse.request().toString(),
                    requestResponse.hasResponse() ? requestResponse.response().toString() : "",
                    safeTargetUrl(requestResponse),
                    safeHttpMethod(requestResponse),
                    "scanner-request-" + (count + 1)
            ));
            count++;
        }
        return entries;
    }

    private List<Map<String, Object>> buildCurrentRequestContext(AssessmentRequest payload) {
        if (payload == null || firstNonBlank(payload.getRawRequest(), "").isBlank()) {
            return List.of();
        }
        return List.of(buildRequestContextEntry(
                payload.getRawRequest(),
                payload.getRawResponse(),
                payload.getTargetUrl(),
                payload.getHttpMethod(),
                "current-request"
        ));
    }

    private Map<String, Object> buildRequestContextEntry(
            String rawRequest,
            String rawResponse,
            String targetUrl,
            String httpMethod,
            String summary
    ) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("summary", firstNonBlank(summary, "request-context"));
        entry.put("method", firstNonBlank(httpMethod, ""));
        entry.put("url", firstNonBlank(targetUrl, ""));
        entry.put("status_code", parseStatusCode(rawResponse));
        entry.put("request_ref", "");
        entry.put("response_ref", "");
        entry.put("has_request", rawRequest != null && !rawRequest.isBlank());
        entry.put("has_response", rawResponse != null && !rawResponse.isBlank());
        return entry;
    }

    private String parseStatusCode(String rawResponse) {
        String text = firstNonBlank(rawResponse, "").trim();
        if (text.isBlank()) {
            return "";
        }
        String[] lines = text.replace("\r\n", "\n").split("\n", 2);
        Matcher matcher = Pattern.compile("\\s(\\d{3})\\b").matcher(lines[0]);
        return matcher.find() ? matcher.group(1) : "";
    }

    private Map<String, Object> buildProjectConfigSnapshot() {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("selected_profile", firstNonBlank(resultsTab.selectedProfile(), ""));
        snapshot.put("enabled_tools", compactLineList(resultsTab.savedBurpToolsText()));
        snapshot.put("scope_includes", resultsTab.reviewScopeIncludeClasses());
        snapshot.put("scope_excludes", resultsTab.reviewScopeExcludeClasses());
        snapshot.put("rate_limit_notes", compactSingleLine(resultsTab.rateLimitText(), 220));
        snapshot.put("concurrency_notes", compactSingleLine(resultsTab.maxConcurrencyText(), 220));
        snapshot.put("custom_headers_notes", compactSingleLine(resultsTab.customHeadersText(), 220));
        snapshot.put("program_policy", compactSingleLine(resultsTab.programPolicyText(), 260));
        snapshot.put("config_warnings", compactLineList(resultsTab.burpScreenshotAuditText()));
        return snapshot;
    }

    private List<String> compactLineList(String text) {
        List<String> lines = new ArrayList<>();
        String value = firstNonBlank(text, "");
        if (value.isBlank()) {
            return lines;
        }
        for (String rawLine : value.split("\\R")) {
            String trimmed = compactSingleLine(rawLine, 220);
            if (!trimmed.isBlank() && !lines.contains(trimmed)) {
                lines.add(trimmed);
            }
            if (lines.size() >= 8) {
                break;
            }
        }
        return lines;
    }

    private Optional<HttpRequestResponse> extractRequestResponse(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return Optional.ofNullable(event.messageEditorRequestResponse().get().requestResponse());
        }
        if (!event.selectedRequestResponses().isEmpty()) {
            return Optional.ofNullable(event.selectedRequestResponses().get(0));
        }
        return Optional.empty();
    }

    private AssessmentRequest buildPayload(
            HttpRequestResponse requestResponse,
            String batchId,
            int batchIndex,
            int batchTotal,
            ToolType toolType,
            InvocationType invocationType
    ) {
        String rawRequest = requestResponse.request().toString();
        String rawResponse = requestResponse.hasResponse() ? requestResponse.response().toString() : "";

        List<String> annotations = new ArrayList<>(requestResponse.hasResponse()
                ? List.of("response_present", "advisory_only")
                : List.of("response_missing", "advisory_only"));
        appendBurpOriginAnnotations(annotations, toolType, invocationType);

        AssessmentRequest payload = new AssessmentRequest(
                rawRequest,
                rawResponse,
                safeTargetUrl(requestResponse),
                safeHttpMethod(requestResponse),
                buildSourceToolLabel(toolType, invocationType, false),
                true,
                annotations,
                batchId,
                batchIndex,
                batchTotal,
                Map.of(),
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                resultsTab.effectiveBurpConfigExportText(),
                resultsTab.autoUseSavedSettings() ? resultsTab.burpScreenshotAuditText() : "",
                resultsTab.autoUseSavedSettings() ? resultsTab.savedBurpToolsText() : "",
                resultsTab.autoUseSavedSettings() ? resultsTab.savedProgramPolicyText() : "",
                resultsTab.autoUseSavedSettings() ? resultsTab.savedProgramScreenshotText() : "",
                "",
                List.of(),
                List.of(),
                "",
                "",
                "",
                "",
                "",
                resultsTab.selectedProfile(),
                resultsTab.reviewScopeIncludeClasses(),
                resultsTab.reviewScopeExcludeClasses(),
                Map.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                Map.of()
        );
        applyOperatorRoutingAnnotations(payload);
        enrichPayloadWithBurpContext(payload);
        return payload;
    }

    private AssessmentRequest buildPayloadFromIssues(List<AuditIssue> issues, ToolType toolType, InvocationType invocationType) {
        HttpRequestResponse anchor = representativeRequestResponse(issues);
        String rawRequest = anchor != null ? anchor.request().toString() : "";
        String rawResponse = anchor != null && anchor.hasResponse() ? anchor.response().toString() : "";
        String targetUrl = anchor != null ? safeTargetUrl(anchor) : firstIssueBaseUrl(issues);
        String httpMethod = anchor != null ? safeHttpMethod(anchor) : "UNKNOWN";

        List<String> annotations = new ArrayList<>(List.of("audit_issue_selected", "advisory_only"));
        appendBurpOriginAnnotations(annotations, toolType, invocationType);
        if (anchor != null && anchor.hasResponse()) {
            annotations.add("response_present");
        } else {
            annotations.add("response_missing");
        }

        AssessmentRequest payload = new AssessmentRequest(
                rawRequest,
                rawResponse,
                targetUrl,
                httpMethod,
                buildSourceToolLabel(toolType, invocationType, true),
                true,
                annotations,
                "",
                0,
                0,
                Map.of(),
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                summarizeSelectedIssues(targetUrl, issues),
                resultsTab.effectiveBurpConfigExportText(),
                resultsTab.autoUseSavedSettings() ? resultsTab.burpScreenshotAuditText() : "",
                resultsTab.autoUseSavedSettings() ? resultsTab.savedBurpToolsText() : "",
                resultsTab.autoUseSavedSettings() ? resultsTab.savedProgramPolicyText() : "",
                resultsTab.autoUseSavedSettings() ? resultsTab.savedProgramScreenshotText() : "",
                "",
                List.of(),
                List.of(),
                "",
                summarizeSelectedIssues(targetUrl, issues),
                "",
                summarizeSelectedIssueInteractions(targetUrl, issues),
                "",
                resultsTab.selectedProfile(),
                resultsTab.reviewScopeIncludeClasses(),
                resultsTab.reviewScopeExcludeClasses(),
                Map.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                Map.of()
        );
        seedSelectedScannerContext(payload, issues);
        applyOperatorRoutingAnnotations(payload);
        enrichPayloadWithBurpContext(payload);
        return payload;
    }

    private String describeRequestOrigin(ContextMenuEvent event) {
        ToolType toolType = event.toolType();
        if (toolType == ToolType.REPEATER) {
            return "Repeater Request";
        }
        if (toolType == ToolType.INTRUDER) {
            return "Intruder Request";
        }
        if (toolType == ToolType.SCANNER) {
            return "Scanner Request";
        }
        return "Request";
    }

    private String describeIssueOrigin(ContextMenuEvent event) {
        return event.toolType() == ToolType.SCANNER ? "Scanner Audit Issue" : "Issue";
    }

    private String buildSourceToolLabel(ToolType toolType, InvocationType invocationType, boolean issuePayload) {
        StringBuilder builder = new StringBuilder("burp-suite-montoya");
        if (toolType != null) {
            builder.append("-").append(toolType.name().toLowerCase());
        }
        if (invocationType != null) {
            builder.append("-").append(invocationType.name().toLowerCase());
        }
        builder.append(issuePayload ? "-audit-issue" : "-request");
        return builder.toString();
    }

    private void appendBurpOriginAnnotations(List<String> annotations, ToolType toolType, InvocationType invocationType) {
        if (toolType != null) {
            annotations.add("tool_" + toolType.name().toLowerCase());
            switch (toolType) {
                case REPEATER -> annotations.add("repeater_context");
                case INTRUDER -> annotations.add("intruder_context");
                case SCANNER -> annotations.add("scanner_context");
                default -> {
                }
            }
        }
        if (invocationType != null) {
            annotations.add("invocation_" + invocationType.name().toLowerCase());
            switch (invocationType) {
                case MESSAGE_EDITOR_REQUEST, MESSAGE_VIEWER_REQUEST -> annotations.add("request_editor_context");
                case MESSAGE_EDITOR_RESPONSE, MESSAGE_VIEWER_RESPONSE -> annotations.add("response_view_context");
                case SCANNER_RESULTS -> annotations.add("scanner_results_context");
                case INTRUDER_PAYLOAD_POSITIONS, INTRUDER_ATTACK_RESULTS -> annotations.add("intruder_results_context");
                default -> {
                }
            }
        }
    }

    private HttpRequestResponse representativeRequestResponse(List<AuditIssue> issues) {
        for (AuditIssue issue : issues) {
            if (!issue.requestResponses().isEmpty()) {
                return issue.requestResponses().get(0);
            }
        }
        return null;
    }

    private String firstIssueBaseUrl(List<AuditIssue> issues) {
        for (AuditIssue issue : issues) {
            String baseUrl = firstNonBlank(issue.baseUrl(), "");
            if (!baseUrl.isBlank()) {
                return baseUrl;
            }
        }
        return "unknown-target";
    }

    private void enrichPayloadWithBurpContext(AssessmentRequest payload) {
        if (payload == null) {
            return;
        }

        payload.setUseBurpMcpContext(true);
        payload.setProjectConfigSnapshot(buildProjectConfigSnapshot());
        if (payload.getRepeaterRequests().isEmpty()) {
            payload.setRepeaterRequests(buildCurrentRequestContext(payload));
        }

        List<AuditIssue> siteIssues = findIssuesForTarget(payload.getTargetUrl());
        if (siteIssues.isEmpty()) {
            return;
        }

        Map<String, Object> dashboardIssue = payload.getBurpDashboardIssue();
        String anchorFamily = issueFamilyFromContext(dashboardIssue);
        String anchorPath = normalizedTargetPrefix(firstNonBlank(String.valueOf(dashboardIssue.getOrDefault("url", "")), payload.getTargetUrl()));

        List<AuditIssue> relatedIssues = new ArrayList<>();
        for (AuditIssue issue : siteIssues) {
            if (issue == null) {
                continue;
            }
            String issuePath = normalizedTargetPrefix(firstNonBlank(issue.baseUrl(), ""));
            if (!anchorPath.isBlank() && !anchorPath.equals(issuePath)) {
                continue;
            }
            String issueFamily = issueFamily(issue);
            if (!anchorFamily.equals("general")) {
                if (anchorFamily.equals(issueFamily) || "general".equals(issueFamily)) {
                    relatedIssues.add(issue);
                }
            } else {
                relatedIssues.add(issue);
            }
            if (relatedIssues.size() >= MAX_AUTO_ISSUES) {
                break;
            }
        }

        if (!dashboardIssue.isEmpty()) {
            relatedIssues.removeIf(issue ->
                    firstNonBlank(issue.name(), "").equals(String.valueOf(dashboardIssue.getOrDefault("name", "")))
                            && firstNonBlank(issue.baseUrl(), "").equals(String.valueOf(dashboardIssue.getOrDefault("url", "")))
            );
            payload.setBurpRelatedScannerIssues(buildIssueContextList(relatedIssues, false));
        }

        String autoBapp = summarizeAuditIssues(payload.getTargetUrl(), relatedIssues);
        String autoCollaborator = summarizeCollaboratorInteractions(payload.getTargetUrl(), relatedIssues);

        payload.setBappFindingsText(mergeEvidence(autoBapp, payload.getBappFindingsText(), "Manual BApp notes"));
        payload.setCollaboratorEvidenceText(mergeEvidence(autoCollaborator, payload.getCollaboratorEvidenceText(), "Manual Collaborator notes"));

        int interactionCount = 0;
        for (AuditIssue issue : relatedIssues) {
            interactionCount += issue.collaboratorInteractions().size();
        }

        api.logging().logToOutput(
                "AI Bridge auto-attached " + relatedIssues.size() + " related Burp issue(s) and "
                        + interactionCount + " linked Collaborator interaction(s) for " + payload.getTargetUrl()
        );
    }

    private List<AuditIssue> findIssuesForTarget(String targetUrl) {
        String prefix = normalizedTargetPrefix(targetUrl);
        if (prefix.isBlank()) {
            return List.of();
        }

        List<AuditIssue> issues = new ArrayList<>(api.siteMap().issues(SiteMapFilter.prefixFilter(prefix)));
        if (!issues.isEmpty()) {
            return issues;
        }

        String serviceRoot = normalizedServiceRoot(targetUrl);
        if (serviceRoot.isBlank() || serviceRoot.equals(prefix)) {
            return List.of();
        }

        List<AuditIssue> broadMatches = api.siteMap().issues(SiteMapFilter.prefixFilter(serviceRoot));
        List<AuditIssue> filtered = new ArrayList<>();
        for (AuditIssue issue : broadMatches) {
            String issueBaseUrl = firstNonBlank(issue.baseUrl(), "");
            if (!issueBaseUrl.isBlank() && issueBaseUrl.startsWith(prefix)) {
                filtered.add(issue);
            }
        }
        return filtered;
    }

    private String summarizeAuditIssues(String targetUrl, List<AuditIssue> issues) {
        if (issues.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        builder.append("Auto-collected Burp audit issues for ").append(normalizedTargetPrefix(targetUrl)).append(":");
        int count = 0;
        for (AuditIssue issue : issues) {
            if (count >= MAX_AUTO_ISSUES) {
                break;
            }
            builder.append(System.lineSeparator()).append("- ")
                    .append(firstNonBlank(issue.name(), "Unnamed issue"))
                    .append(" | severity: ").append(issue.severity())
                    .append(" | confidence: ").append(issue.confidence());

            String baseUrl = firstNonBlank(issue.baseUrl(), "");
            if (!baseUrl.isBlank()) {
                builder.append(" | url: ").append(baseUrl);
            }

            String detail = compactSingleLine(issue.detail(), 220);
            if (!detail.isBlank()) {
                builder.append(" | detail: ").append(detail);
            }

            if (!issue.collaboratorInteractions().isEmpty()) {
                builder.append(" | collaborator interactions: ").append(issue.collaboratorInteractions().size());
            }
            count++;
        }

        if (issues.size() > MAX_AUTO_ISSUES) {
            builder.append(System.lineSeparator())
                    .append("- ... ").append(issues.size() - MAX_AUTO_ISSUES).append(" more issue(s) omitted.");
        }
        return builder.toString();
    }

    private String summarizeSelectedIssues(String targetUrl, List<AuditIssue> issues) {
        if (issues.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        builder.append("Selected Burp audit issue(s) for ").append(normalizedTargetPrefix(targetUrl)).append(":");
        HttpRequestResponse anchor = representativeRequestResponse(issues);
        if (anchor != null) {
            builder.append(System.lineSeparator())
                    .append("- Full anchor request was forwarded to AI Bridge for this finding.");
            String preview = requestPreview(anchor.request().toString());
            if (!preview.isBlank()) {
                builder.append(System.lineSeparator())
                        .append("- Request preview: ")
                        .append(preview);
            }
        }
        int count = 0;
        for (AuditIssue issue : issues) {
            if (count >= MAX_AUTO_ISSUES) {
                break;
            }
            builder.append(System.lineSeparator()).append("- ")
                    .append(firstNonBlank(issue.name(), "Unnamed issue"))
                    .append(" | severity: ").append(issue.severity())
                    .append(" | confidence: ").append(issue.confidence());

            String baseUrl = firstNonBlank(issue.baseUrl(), "");
            if (!baseUrl.isBlank()) {
                builder.append(" | url: ").append(baseUrl);
            }

            String detail = compactSingleLine(issue.detail(), 240);
            if (!detail.isBlank()) {
                builder.append(" | detail: ").append(detail);
            }

            String highlight = issueHighlightExcerpt(issue);
            if (!highlight.isBlank()) {
                builder.append(" | likely highlighted excerpt: ").append(highlight);
            }

            String remediation = compactSingleLine(issue.remediation(), 180);
            if (!remediation.isBlank()) {
                builder.append(" | remediation: ").append(remediation);
            }
            count++;
        }
        return builder.toString();
    }

    private String issueHighlightExcerpt(AuditIssue issue) {
        String detail = htmlToPlainText(firstNonBlank(issue.detail(), ""));
        if (detail.isBlank()) {
            return "";
        }
        Matcher quoted = Pattern.compile("\"([^\"]{8,220})\"").matcher(detail);
        if (quoted.find()) {
            return compactSingleLine(quoted.group(1), 180);
        }
        Matcher xmlLike = Pattern.compile("(<[^>]{4,220}>)").matcher(detail);
        if (xmlLike.find()) {
            return compactSingleLine(xmlLike.group(1), 180);
        }
        return compactSingleLine(detail, 180);
    }

    private String requestPreview(String rawRequest) {
        String value = firstNonBlank(rawRequest, "").trim();
        if (value.isBlank()) {
            return "";
        }
        String[] lines = value.replace("\r\n", "\n").split("\n");
        StringBuilder preview = new StringBuilder();
        for (int index = 0; index < Math.min(lines.length, 10); index++) {
            if (index > 0) {
                preview.append(" | ");
            }
            preview.append(lines[index].trim());
        }
        return compactSingleLine(preview.toString(), 240);
    }

    private String htmlToPlainText(String text) {
        String value = firstNonBlank(text, "");
        if (value.isBlank()) {
            return "";
        }
        return value
                .replaceAll("(?i)<br\\s*/?>", " ")
                .replaceAll("(?i)</p>", " ")
                .replaceAll("<[^>]+>", " ")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replaceAll("\\s+", " ")
                .trim();
    }

    private String summarizeCollaboratorInteractions(String targetUrl, List<AuditIssue> issues) {
        List<String> lines = new ArrayList<>();
        for (AuditIssue issue : issues) {
            for (Interaction interaction : issue.collaboratorInteractions()) {
                if (lines.size() >= MAX_AUTO_INTERACTIONS) {
                    break;
                }

                StringBuilder line = new StringBuilder();
                line.append("- ")
                        .append(firstNonBlank(issue.name(), "Unnamed issue"))
                        .append(" | ").append(interaction.type())
                        .append(" | ").append(interaction.timeStamp());

                interaction.dnsDetails().ifPresent(dns ->
                        line.append(" | dns: ")
                                .append(dns.queryType())
                                .append(" ")
                                .append(compactSingleLine(String.valueOf(dns.query()), 120))
                );

                interaction.httpDetails().ifPresent(http -> {
                    String interactionUrl = safeTargetUrl(http.requestResponse());
                    if (!interactionUrl.isBlank()) {
                        line.append(" | url: ").append(interactionUrl);
                    }
                    line.append(" | protocol: ").append(http.protocol());
                });

                interaction.smtpDetails().ifPresent(smtp ->
                        line.append(" | smtp: ").append(compactSingleLine(smtp.conversation(), 120))
                );

                interaction.customData().ifPresent(custom ->
                        line.append(" | custom: ").append(compactSingleLine(String.valueOf(custom), 120))
                );

                line.append(" | client: ").append(interaction.clientIp().getHostAddress()).append(":").append(interaction.clientPort());
                lines.add(line.toString());
            }
            if (lines.size() >= MAX_AUTO_INTERACTIONS) {
                break;
            }
        }

        if (lines.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        builder.append("Auto-collected Collaborator interactions linked to Burp issues for ")
                .append(normalizedTargetPrefix(targetUrl))
                .append(":");
        for (String line : lines) {
            builder.append(System.lineSeparator()).append(line);
        }
        return builder.toString();
    }

    private String summarizeSelectedIssueInteractions(String targetUrl, List<AuditIssue> issues) {
        if (issues.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        builder.append("Selected audit issue linked Collaborator interactions for ")
                .append(normalizedTargetPrefix(targetUrl))
                .append(":");
        int count = 0;
        for (AuditIssue issue : issues) {
            for (Interaction interaction : issue.collaboratorInteractions()) {
                if (count >= MAX_AUTO_INTERACTIONS) {
                    return builder.toString();
                }
                builder.append(System.lineSeparator()).append("- ")
                        .append(firstNonBlank(issue.name(), "Unnamed issue"))
                        .append(" | ").append(interaction.type())
                        .append(" | ").append(interaction.timeStamp());

                interaction.httpDetails().ifPresent(http ->
                        builder.append(" | protocol: ").append(http.protocol())
                );
                interaction.dnsDetails().ifPresent(dns ->
                        builder.append(" | dns: ").append(dns.queryType())
                );
                interaction.smtpDetails().ifPresent(smtp ->
                        builder.append(" | smtp")
                );
                count++;
            }
        }

        return count == 0 ? "" : builder.toString();
    }

    private String summarizeStandaloneCollaboratorInteractions(List<Interaction> interactions) {
        if (interactions.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        builder.append("AI Bridge synced Collaborator interactions:");
        int count = 0;
        for (Interaction interaction : interactions) {
            if (count >= MAX_AUTO_INTERACTIONS) {
                break;
            }
            builder.append(System.lineSeparator()).append("- ")
                    .append(interaction.type())
                    .append(" | ").append(interaction.timeStamp());

            interaction.dnsDetails().ifPresent(dns ->
                    builder.append(" | dns: ")
                            .append(dns.queryType())
                            .append(" ")
                            .append(compactSingleLine(String.valueOf(dns.query()), 120))
            );

            interaction.httpDetails().ifPresent(http -> {
                String interactionUrl = safeTargetUrl(http.requestResponse());
                if (!interactionUrl.isBlank()) {
                    builder.append(" | url: ").append(interactionUrl);
                }
                builder.append(" | protocol: ").append(http.protocol());
            });

            interaction.smtpDetails().ifPresent(smtp ->
                    builder.append(" | smtp: ").append(compactSingleLine(smtp.conversation(), 120))
            );

            interaction.customData().ifPresent(custom ->
                    builder.append(" | custom: ").append(compactSingleLine(custom, 120))
            );

            builder.append(" | client: ")
                    .append(interaction.clientIp().getHostAddress())
                    .append(":")
                    .append(interaction.clientPort());
            count++;
        }

        if (interactions.size() > MAX_AUTO_INTERACTIONS) {
            builder.append(System.lineSeparator())
                    .append("- ... ").append(interactions.size() - MAX_AUTO_INTERACTIONS).append(" more interaction(s) omitted.");
        }
        return builder.toString();
    }

    private String stripManagedCollaboratorSyncSection(String text) {
        String value = firstNonBlank(text, "").trim();
        if (!value.startsWith("AI Bridge synced Collaborator interactions:")) {
            return value;
        }

        String marker = "Manual Collaborator notes:";
        int markerIndex = value.indexOf(marker);
        if (markerIndex == -1) {
            return "";
        }
        return value.substring(markerIndex + marker.length()).trim();
    }

    private String mergeEvidence(String autoText, String manualText, String manualLabel) {
        String auto = firstNonBlank(autoText, "").trim();
        String manual = firstNonBlank(manualText, "").trim();
        if (auto.isBlank()) {
            return manual;
        }
        if (manual.isBlank()) {
            return auto;
        }
        if (manual.contains(auto)) {
            return manual;
        }
        return auto + System.lineSeparator() + System.lineSeparator() + manualLabel + ":" + System.lineSeparator() + manual;
    }

    private void mergeNonBlankAnswers(Map<String, String> target, Map<String, String> updates) {
        if (updates == null || updates.isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : updates.entrySet()) {
            String value = firstNonBlank(entry.getValue(), "").trim();
            if (!value.isBlank()) {
                target.put(entry.getKey(), value);
            }
        }
    }

    private String preferCurrentText(String currentValue, String existingValue) {
        String current = firstNonBlank(currentValue, "").trim();
        if (!current.isBlank()) {
            return current;
        }
        return firstNonBlank(existingValue, "");
    }

    private List<String> preferCurrentList(List<String> currentValue, List<String> existingValue) {
        if (currentValue != null && !currentValue.isEmpty()) {
            return currentValue;
        }
        return existingValue == null ? List.of() : existingValue;
    }

    private String normalizedTargetPrefix(String targetUrl) {
        String target = firstNonBlank(targetUrl, "").trim();
        if (target.isBlank()) {
            return "";
        }
        try {
            URI uri = new URI(target);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return target.split("\\?", 2)[0];
            }
            StringBuilder builder = new StringBuilder();
            builder.append(uri.getScheme()).append("://").append(uri.getHost());
            if (uri.getPort() != -1 && uri.getPort() != uri.toURL().getDefaultPort()) {
                builder.append(":").append(uri.getPort());
            }
            String path = firstNonBlank(uri.getPath(), "/");
            builder.append(path.isBlank() ? "/" : path);
            return builder.toString();
        } catch (Exception ignored) {
            return target.split("\\?", 2)[0];
        }
    }

    private String normalizedServiceRoot(String targetUrl) {
        String target = firstNonBlank(targetUrl, "").trim();
        if (target.isBlank()) {
            return "";
        }
        try {
            URI uri = new URI(target);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return "";
            }
            StringBuilder builder = new StringBuilder();
            builder.append(uri.getScheme()).append("://").append(uri.getHost());
            if (uri.getPort() != -1 && uri.getPort() != uri.toURL().getDefaultPort()) {
                builder.append(":").append(uri.getPort());
            }
            builder.append("/");
            return builder.toString();
        } catch (URISyntaxException ignored) {
            return "";
        } catch (Exception ignored) {
            return "";
        }
    }

    private String compactSingleLine(String text, int maxLength) {
        String normalized = firstNonBlank(text, "").replace("\r\n", " ").replace("\n", " ").trim();
        if (normalized.length() <= maxLength) {
            return normalized;
        }
        return normalized.substring(0, maxLength) + "...";
    }

    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private String safeTargetUrl(HttpRequestResponse requestResponse) {
        try {
            return String.valueOf(requestResponse.request().url());
        } catch (Exception ignored) {
            return "unknown-target";
        }
    }

    private String safeHttpMethod(HttpRequestResponse requestResponse) {
        try {
            return String.valueOf(requestResponse.request().method());
        } catch (Exception ignored) {
            return "UNKNOWN";
        }
    }

    private String rootCauseMessage(Throwable throwable) {
        Throwable cursor = throwable;
        while (cursor.getCause() != null) {
            cursor = cursor.getCause();
        }
        return cursor.getMessage() == null ? cursor.toString() : cursor.getMessage();
    }

    private record ParsedUrlLines(List<String> urls, List<String> invalidLines) {
    }

    private record ParsedHeaderRules(Map<String, String> headers, List<String> invalidLines) {
    }

    private static final class InvestigationSessionState {
        public String sessionId;
        public String title;
        public String requestDraft;
        public String chatTranscript;
        public List<ResultsTab.InvestigationTranscriptState> transcriptEntries = new ArrayList<>();
        public List<ResultsTab.InvestigationNotebookEntryState> notebookEntries = new ArrayList<>();
        public String statusText;
        public AssessmentRequest payload;
    }

    private final class BatchAccumulator {
        private final int totalRequests;
        private final String batchId;
        private int completedRequests;
        private int failedRequests;
        private final Map<String, Integer> classCounts;
        private final LinkedHashSet<String> combinedTags;
        private final LinkedHashSet<String> followUpQuestions;
        private final LinkedHashSet<String> sourceLinks;
        private final List<String> itemSummaries;
        private String firstWordlist;

        private BatchAccumulator(String batchId, int totalRequests) {
            this.batchId = batchId;
            this.totalRequests = totalRequests;
            this.classCounts = new LinkedHashMap<>();
            this.combinedTags = new LinkedHashSet<>();
            this.followUpQuestions = new LinkedHashSet<>();
            this.sourceLinks = new LinkedHashSet<>();
            this.itemSummaries = new ArrayList<>();
        }

        private void recordSuccess(AssessmentRequest payload, AdvisoryResponse response) {
            completedRequests++;
            for (String vulnerability : response.getPotentialVulnerabilities()) {
                classCounts.merge(extractVulnClass(vulnerability), 1, Integer::sum);
            }
            splitTags(response.getNucleiTags()).forEach(combinedTags::add);
            if ((firstWordlist == null || firstWordlist.isBlank()) && response.getSeclistsPath() != null && !response.getSeclistsPath().isBlank()) {
                firstWordlist = response.getSeclistsPath();
            }
            followUpQuestions.addAll(response.getQuestionsForUser());
            sourceLinks.addAll(response.getSourceLinks());
            itemSummaries.add(payload.getTargetUrl() + " -> " + firstNonBlank(response.getAnalysis(), "No analysis text"));
        }

        private void recordFailure(AssessmentRequest payload, String message) {
            failedRequests++;
            itemSummaries.add(payload.getTargetUrl() + " -> FAILED: " + firstNonBlank(message, "Unknown error"));
        }

        private String summaryText() {
            StringBuilder builder = new StringBuilder();
            builder.append("Batch ID: ").append(batchId).append(System.lineSeparator()).append(System.lineSeparator());
            builder.append("Batch analysis finished. Completed ")
                    .append(completedRequests)
                    .append(" of ")
                    .append(totalRequests)
                    .append(" requests.");
            if (failedRequests > 0) {
                builder.append(System.lineSeparator()).append("Failures: ").append(failedRequests).append(".");
            }
            builder.append(System.lineSeparator()).append(System.lineSeparator())
                    .append("Export JSON: ")
                    .append(resultsTab.endpointUrl().replace("/api/analyze", "/api/history/batches/" + batchId))
                    .append(System.lineSeparator())
                    .append("Export Markdown: ")
                    .append(resultsTab.endpointUrl().replace("/api/analyze", "/api/history/batches/" + batchId + "/export.md"));
            builder.append(System.lineSeparator()).append(System.lineSeparator()).append("Per-request summary:");
            for (String item : itemSummaries) {
                builder.append(System.lineSeparator()).append("- ").append(item);
            }
            return builder.toString();
        }

        private String groupedFindingsText() {
            if (classCounts.isEmpty()) {
                return failedRequests > 0
                        ? "No grouped vulnerability classes were produced. Review the per-request failures in the analysis summary."
                        : "No classified vulnerability groups were identified across this batch.";
            }
            StringBuilder builder = new StringBuilder();
            for (Map.Entry<String, Integer> entry : classCounts.entrySet()) {
                if (builder.length() > 0) {
                    builder.append(System.lineSeparator()).append(System.lineSeparator());
                }
                builder.append("- ").append(entry.getKey()).append(": ").append(entry.getValue()).append(" hit(s)");
            }
            return builder.toString();
        }

        private String combinedTags() {
            return String.join(",", combinedTags);
        }

        private String suggestedWordlist() {
            return firstWordlist;
        }

        private List<String> followUpQuestions() {
            return new ArrayList<>(followUpQuestions).subList(0, Math.min(3, followUpQuestions.size()));
        }

        private String sourceLinksText() {
            if (sourceLinks.isEmpty()) {
                return "No source links were provided.";
            }
            return String.join(System.lineSeparator(), sourceLinks);
        }

        private List<String> splitTags(String tags) {
            if (tags == null || tags.isBlank()) {
                return List.of();
            }
            String[] parts = tags.split(",");
            List<String> values = new ArrayList<>();
            for (String part : parts) {
                String normalized = part.trim();
                if (!normalized.isBlank()) {
                    values.add(normalized);
                }
            }
            return values;
        }

        private String extractVulnClass(String text) {
            if (text == null || text.isBlank()) {
                return "general";
            }
            Matcher matcher = VULN_CLASS_PATTERN.matcher(text);
            return matcher.find() ? matcher.group(1) : "general";
        }

        private String firstNonBlank(String value, String fallback) {
            return value == null || value.isBlank() ? fallback : value;
        }
    }
}
