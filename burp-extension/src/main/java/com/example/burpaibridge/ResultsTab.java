package com.example.burpaibridge;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JOptionPane;
import javax.swing.Scrollable;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ResultsTab {
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final int QUESTIONS_HEIGHT = 180;
    private static final String DEFAULT_RUNTIME_STRATEGY = "Automatic (MCP-first)";
    private static final String DEFAULT_PROVIDER_ROUTE = "Context: Burp MCP | Reasoning: local AI | Time budget: Balanced";
    private static final String DEFAULT_INVESTIGATION_HELP = "Send a Scanner issue, Repeater request, or Intruder request to AI Bridge to open an investigation workspace here.";
    private static final String SUGGESTION_FOLLOW_UP_KEY = "Suggestion follow-up request";
    private static final Pattern ROUTED_MODEL_PATTERN = Pattern.compile("model=([^\\s]+)");
    private static final Pattern INVESTIGATION_TRANSCRIPT_HEADER_PATTERN =
            Pattern.compile("(?m)^\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})] (You|AI Bridge|System):\\R");
    private static final int STUCK_JOB_WARNING_MILLIS = 25000;
    private static final Font NARRATIVE_FONT = new Font(Font.SERIF, Font.PLAIN, 15);
    private static final Font FORM_FONT = new Font(Font.SANS_SERIF, Font.PLAIN, 13);
    private static final Font HELPER_FONT = new Font(Font.SANS_SERIF, Font.PLAIN, 13);
    private static final Font CODE_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private static final Color HELPER_COLOR = new Color(0x667085);
    private static final Color SUBTLE_PANEL = new Color(0xF8FAFC);
    // Keep these indexes aligned with buildWorkspaceTabs().
    private static final int WORKSPACE_TAB_INVESTIGATIONS = 0;
    private static final int WORKSPACE_TAB_ADVISORY = 1;
    private static final int WORKSPACE_TAB_SUGGESTIONS = 2;
    private static final int WORKSPACE_TAB_EVIDENCE = 3;
    private static final int WORKSPACE_TAB_SETTINGS = 4;
    private static final String RESULTS_TAB_REQUEST_PLAN = "Request Plan";
    private static final String RESULTS_TAB_AI_ANALYSIS = "AI Analysis";
    private static final String RESULTS_TAB_FINDINGS = "Findings";
    private static final String RESULTS_TAB_REASONING = "Reasoning";
    private static final String RESULTS_TAB_TOOLING = "Tooling";
    private static final String RESULTS_TAB_WORKFLOW = "Workflow";
    private static final List<String> ALL_REVIEW_CLASSES = List.of(
            "access-control",
            "authentication",
            "business-logic",
            "cache",
            "command-injection",
            "cors",
            "crypto-failures",
            "csrf",
            "deserialization",
            "file-upload",
            "graphql",
            "http-request-smuggling",
            "information-disclosure",
            "input-validation",
            "insecure-design",
            "jwt-token",
            "mass-assignment",
            "open-redirect",
            "path-traversal",
            "race-condition",
            "security-misconfiguration",
            "secret-exposure",
            "session-management",
            "sqli",
            "ssti",
            "ssrf",
            "xss",
            "xxe"
    );

    private final JPanel mainPanel;
    private final JTextField endpointField;
    private final JComboBox<String> skipClassCombo;
    private final JTextField activeProfileField;
    private final JTextField providerRouteField;
    private final JTextField scanScopeSummaryField;
    private final JTextField estimatedDurationField;
    private final JTextField complexityField;
    private final JComboBox<String> timeBudgetCombo;
    private final JLabel statusLabel;
    private final JLabel backendHealthLabel;
    private final JLabel targetLabel;
    private final JLabel methodLabel;
    private final JLabel updatedLabel;
    private final JPanel findingChipsPanel;
    private final JPanel confidenceChipsPanel;
    private final JTextField primaryNextActionField;
    private final JTextField toolAvailabilityField;
    private final JTextField projectReadinessField;
    private final JTextArea requestPlanArea;
    private final JTextArea analysisArea;
    private final JTextArea vulnerabilitiesArea;
    private final JTextArea kaliToolsArea;
    private final JTextArea kaliCommandsArea;
    private final JTextArea payloadListsArea;
    private final JTextArea bcheckRecommendationsArea;
    private final JTextArea impactPathsArea;
    private final JTextArea burpSettingsArea;
    private final JTextArea projectReadinessArea;
    private final JTextArea burpActionChecklistArea;
    private final JTextArea sourceLinksArea;
    private final JTextArea suggestionQueueArea;
    private final JTextArea suggestionFollowUpArea;
    private final JTextArea confidenceArea;
    private final JTextArea historyCorrelationArea;
    private final JTextArea confirmationPlaybooksArea;
    private final JTextArea reasoningSummaryArea;
    private final JTextArea phaseHistoryArea;
    private final JTextField nucleiTagsField;
    private final JTextField seclistsPathField;
    private final JPanel questionsPanel;
    private final JPanel questionSectionPanel;
    private final Map<String, JTextField> questionInputs;
    private final ObjectMapper mapper;
    private final JTabbedPane resultsTabs;
    private final JTabbedPane workspaceTabs;
    private final JTabbedPane investigationTabs;
    private final Map<String, InvestigationWorkspace> investigationWorkspaces;
    private final JTextArea investigationHintArea;
    private final JCheckBox reuseRepeaterInvestigationsCheckBox;
    private final JTextField feedbackNotesField;
    private final JLabel feedbackStatusLabel;
    private final JButton usefulFeedbackButton;
    private final JButton truePositiveFeedbackButton;
    private final JButton notUsefulFeedbackButton;
    private final JButton falsePositiveFeedbackButton;
    private final JTextArea toolHelpArea;
    private final JTextArea detectedToolInventoryArea;
    private final JTextArea responseDeltaArea;
    private final JTextArea scopeIncludesArea;
    private final JTextArea scopeExcludesArea;
    private final DefaultListModel<String> skippedScopeModel;
    private final JList<String> skippedScopeList;
    private final JTextField rateLimitField;
    private final JTextField maxConcurrencyField;
    private final JTextArea customHeadersArea;
    private final JTextArea programPolicyArea;
    private final JTextArea toolResultsArea;
    private final JTextArea burpConfigExportArea;
    private final JTextArea burpScreenshotAuditArea;
    private final JTextArea savedLoadedBurpToolsArea;
    private final JTextArea savedProgramPolicyArea;
    private final JTextArea savedProgramScreenshotArea;
    private final JTextArea bappFindingsArea;
    private final JTextArea loggerEvidenceArea;
    private final JTextArea collaboratorEvidenceArea;
    private final JTextField collaboratorPayloadField;
    private final JTextField evidenceSourceField;
    private final JButton addEvidenceButton;
    private final JButton clearEvidenceButton;
    private final JTextArea evidenceTimelineArea;
    private final List<String> evidenceTimelineEntries;
    private final JLabel operatorInputStatusLabel;
    private final JLabel suggestionFollowUpStatusLabel;
    private final JButton submitAnswersButton;
    private final JButton askSuggestionButton;
    private final JButton refreshToolInventoryButton;
    private final JButton copyRequestPlanButton;
    private final JButton copyCommandsButton;
    private final JButton copyPayloadsButton;
    private final JButton copyFullAdvisoryButton;
    private final JButton cancelFollowUpButton;
    private final JButton cancelSuggestionButton;
    private final JButton addSkipClassButton;
    private final JButton removeSkipClassButton;
    private final JButton resetSkipClassesButton;
    private final JButton parseProgramRulesButton;
    private final JButton applyBurpSettingsButton;
    private final JButton disableBurpSettingsButton;
    private final JButton saveSettingsButton;
    private final JButton reloadSettingsButton;
    private final JButton clearSettingsButton;
    private final JTextField reportJsonField;
    private final JTextField reportMarkdownField;
    private final JLabel toolInventoryStatusLabel;
    private final JLabel collaboratorSyncStatusLabel;
    private final JLabel aiBridgeSettingsStatusLabel;
    private final JTextField aiBridgeSettingsProjectField;
    private final JTextField aiBridgeVisionStatusField;
    private final JCheckBox autoUseSavedSettingsCheckBox;
    private final JTextArea scanBridgeSummaryArea;
    private final JTextArea scanBridgeGuidanceArea;
    private final JTextArea newScanHandoffArea;
    private final JLabel scanBridgeStatusLabel;
    private final JTextField scanTargetField;
    private final JComboBox<String> scanTypeCombo;
    private final JComboBox<String> auditConfigurationCombo;
    private final DefaultListModel<String> scanLaunchBcheckModel;
    private final JList<String> scanLaunchBcheckList;
    private final JTextArea scanLaunchStatusArea;
    private final JButton launchScanButton;
    private final JButton useCurrentTargetButton;
    private final JButton addScanBcheckButton;
    private final JButton removeScanBcheckButton;
    private final JButton clearScanBcheckButton;
    private final JButton syncCollaboratorButton;
    private final JButton rotateCollaboratorButton;
    private final JButton copyCollaboratorPayloadButton;
    private final JButton analyzeRecentScanButton;
    private final JButton analyzeCurrentTargetScanButton;
    private final JButton copyNewScanHandoffButton;
    private String latestDetailedWorkflowText;
    private List<String> latestRecommendedScanBchecks;
    private List<String> latestPotentialFindings;
    private AssessmentRequest currentAssessmentRequest;
    private String currentJobId;
    private String activeInvestigationId;
    private BiConsumer<String, String> feedbackSubmitter;
    private Runnable followUpSubmitter;
    private Runnable followUpCanceler;
    private BiConsumer<String, String> investigationChatSubmitter;
    private Consumer<String> investigationSelectionListener;
    private Consumer<String> investigationRepeaterSender;
    private BiConsumer<String, String> investigationRenameListener;
    private Consumer<String> investigationCloseListener;
    private Consumer<Boolean> repeaterReuseSettingListener;
    private Runnable toolInventoryRefresher;
    private Runnable collaboratorSyncer;
    private Runnable collaboratorRotator;
    private Runnable recentScanAnalyzer;
    private Runnable currentTargetScanAnalyzer;
    private Runnable bcheckCatalogOpener;
    private Runnable burpSettingsApplier;
    private Runnable burpSettingsDisabler;
    private Runnable aiBridgeSettingsSaver;
    private Runnable aiBridgeSettingsReloader;
    private Runnable aiBridgeSettingsClearer;
    private Consumer<ScanLaunchRequest> scanLauncher;
    private final Timer jobWatchdogTimer;
    private boolean jobWatchdogActive;
    private boolean stuckWarningShown;
    private long lastJobUpdateAtMillis;
    public ResultsTab(String defaultEndpoint) {
        this.mainPanel = new JPanel(new BorderLayout(12, 12));
        this.mainPanel.setBorder(new EmptyBorder(8, 8, 8, 8));
        this.endpointField = new JTextField(defaultEndpoint);
        this.skipClassCombo = new JComboBox<>(ALL_REVIEW_CLASSES.toArray(new String[0]));
        this.activeProfileField = buildReadOnlyField(DEFAULT_RUNTIME_STRATEGY);
        this.providerRouteField = buildReadOnlyField(DEFAULT_PROVIDER_ROUTE);
        this.scanScopeSummaryField = buildReadOnlyField("Awaiting selected classes");
        this.estimatedDurationField = buildReadOnlyField("Awaiting estimate");
        this.complexityField = buildReadOnlyField("Awaiting estimate");
        this.timeBudgetCombo = new JComboBox<>(new String[]{"Balanced", "Fast", "Deep"});
        this.statusLabel = new JLabel("Idle");
        this.backendHealthLabel = new JLabel("Checking backend startup health...");
        this.targetLabel = new JLabel("No request submitted yet.");
        this.methodLabel = new JLabel("-");
        this.updatedLabel = new JLabel("-");
        this.backendHealthLabel.setForeground(HELPER_COLOR);
        this.findingChipsPanel = buildChipRowPanel();
        this.confidenceChipsPanel = buildChipRowPanel();
        this.primaryNextActionField = buildReadOnlyField("Awaiting recommendation");
        this.toolAvailabilityField = buildReadOnlyField("Awaiting inventory");
        this.projectReadinessField = buildReadOnlyField("Awaiting readiness score");
        this.requestPlanArea = buildReadOnlyTextArea("No request plan yet.");
        this.analysisArea = buildReadOnlyTextArea("Send a request or response to AI Bridge to start an advisory assessment.");
        this.vulnerabilitiesArea = buildReadOnlyTextArea("No findings yet.");
        this.kaliToolsArea = buildReadOnlyTextArea("No Kali tool guidance yet.");
        this.kaliCommandsArea = buildReadOnlyTextArea("No Kali command templates yet.");
        this.payloadListsArea = buildReadOnlyTextArea("No payload starter lists yet.");
        this.bcheckRecommendationsArea = buildReadOnlyTextArea("No upstream BCheck recommendations yet.");
        this.impactPathsArea = buildReadOnlyTextArea("No impact-focused escalation paths yet.");
        this.burpSettingsArea = buildReadOnlyTextArea("No Burp settings recommendations yet.");
        this.projectReadinessArea = buildReadOnlyTextArea("No project readiness checks yet.");
        this.burpActionChecklistArea = buildReadOnlyTextArea("No Burp action checklist yet.");
        this.sourceLinksArea = buildReadOnlyTextArea("No source links yet.");
        this.suggestionQueueArea = buildReadOnlyTextArea("No queued manual suggestions yet.");
        this.suggestionFollowUpArea = new JTextArea();
        this.confidenceArea = buildReadOnlyTextArea("No confidence scoring yet.");
        this.historyCorrelationArea = buildReadOnlyTextArea("No history correlation yet.");
        this.confirmationPlaybooksArea = buildReadOnlyTextArea("No confirmation playbooks yet.");
        this.reasoningSummaryArea = buildReadOnlyTextArea("No stored reasoning summary yet.");
        this.phaseHistoryArea = buildReadOnlyTextArea("No phase history snapshots yet.");
        this.nucleiTagsField = buildReadOnlyField("Awaiting recommendation");
        this.seclistsPathField = buildReadOnlyField("Awaiting recommendation");
        this.questionsPanel = new JPanel(new GridBagLayout());
        this.questionSectionPanel = new JPanel(new BorderLayout(8, 8));
        this.questionInputs = new LinkedHashMap<>();
        this.mapper = new ObjectMapper();
        this.feedbackNotesField = new JTextField();
        this.feedbackStatusLabel = new JLabel("Feedback becomes available after a single completed analysis.");
        this.usefulFeedbackButton = new JButton("Useful");
        this.truePositiveFeedbackButton = new JButton("True Positive");
        this.notUsefulFeedbackButton = new JButton("Not Useful");
        this.falsePositiveFeedbackButton = new JButton("False Positive");
        this.toolHelpArea = new JTextArea(5, 20);
        this.detectedToolInventoryArea = buildReadOnlyTextArea("Refresh to detect Kali WSL tools.");
        this.responseDeltaArea = new JTextArea(4, 20);
        this.scopeIncludesArea = new JTextArea(4, 20);
        this.scopeExcludesArea = new JTextArea(4, 20);
        this.skippedScopeModel = new DefaultListModel<>();
        this.skippedScopeList = new JList<>(skippedScopeModel);
        this.rateLimitField = new JTextField();
        this.maxConcurrencyField = new JTextField();
        this.customHeadersArea = new JTextArea(4, 20);
        this.programPolicyArea = new JTextArea(4, 20);
        this.toolResultsArea = new JTextArea(6, 20);
        this.burpConfigExportArea = new JTextArea(8, 20);
        this.burpScreenshotAuditArea = new JTextArea(6, 20);
        this.savedLoadedBurpToolsArea = new JTextArea(6, 20);
        this.savedProgramPolicyArea = new JTextArea(6, 20);
        this.savedProgramScreenshotArea = new JTextArea(6, 20);
        this.bappFindingsArea = new JTextArea(6, 20);
        this.loggerEvidenceArea = new JTextArea(6, 20);
        this.collaboratorEvidenceArea = new JTextArea(6, 20);
        this.collaboratorPayloadField = buildReadOnlyField("Initializing AI Bridge Collaborator client...");
        this.evidenceSourceField = new JTextField();
        this.addEvidenceButton = new JButton("Add To Timeline");
        this.clearEvidenceButton = new JButton("Clear Timeline");
        this.evidenceTimelineArea = buildReadOnlyTextArea("No evidence captured yet for this request.");
        this.evidenceTimelineEntries = new ArrayList<>();
        this.operatorInputStatusLabel = new JLabel("Type answers, a suggestion follow-up, or program context, then submit another AI follow-up.");
        this.suggestionFollowUpStatusLabel = new JLabel("Draft a suggestion-specific follow-up here, then send it to the AI when ready.");
        this.submitAnswersButton = new JButton("Ask AI Follow-Up");
        this.askSuggestionButton = new JButton("Ask AI Follow-Up");
        this.refreshToolInventoryButton = new JButton("Refresh Inventory");
        this.copyRequestPlanButton = new JButton("Copy Plan");
        this.copyCommandsButton = new JButton("Copy Commands");
        this.copyPayloadsButton = new JButton("Copy Payloads");
        this.copyFullAdvisoryButton = new JButton("Copy Advisory");
        this.cancelFollowUpButton = new JButton("Stop");
        this.cancelSuggestionButton = new JButton("Stop");
        this.addSkipClassButton = new JButton("Skip");
        this.removeSkipClassButton = new JButton("Unskip Selected");
        this.resetSkipClassesButton = new JButton("Reset Scope");
        this.parseProgramRulesButton = new JButton("Parse Program Rules");
        this.applyBurpSettingsButton = new JButton("Apply Scope + Headers");
        this.disableBurpSettingsButton = new JButton("Disable Synced Rules");
        this.saveSettingsButton = new JButton("Save Settings");
        this.reloadSettingsButton = new JButton("Reload Saved");
        this.clearSettingsButton = new JButton("Clear Project");
        this.reportJsonField = buildReadOnlyField("Awaiting completed job");
        this.reportMarkdownField = buildReadOnlyField("Awaiting completed job");
        this.toolInventoryStatusLabel = new JLabel("Kali tool inventory has not been fetched yet.");
        this.collaboratorSyncStatusLabel = new JLabel("AI Bridge Collaborator client is not synced yet.");
        this.aiBridgeSettingsStatusLabel = new JLabel("AI-Bridge project settings are not loaded yet.");
        this.aiBridgeSettingsProjectField = buildReadOnlyField("Awaiting Burp project context");
        this.aiBridgeVisionStatusField = buildReadOnlyField("No screenshot vision review has run yet.");
        this.autoUseSavedSettingsCheckBox = new JCheckBox("Use saved AI-Bridge settings automatically in advisories and scan guidance", true);
        this.scanBridgeSummaryArea = buildReadOnlyTextArea("No Burp scan issues have been observed by AI Bridge yet.");
        this.scanBridgeGuidanceArea = buildReadOnlyTextArea(
                "AI Bridge tracks Burp scanner findings, but it only analyzes them when you explicitly review selected issues or recent findings."
        );
        this.newScanHandoffArea = buildReadOnlyTextArea(
                "AI Bridge will build a phased Burp workflow and reporting handoff here once it has issue-specific guidance and your operator constraints."
        );
        this.scanBridgeStatusLabel = new JLabel("Burp scan monitoring is active. Scanner findings are available for manual AI Bridge review.");
        this.scanTargetField = new JTextField();
        this.scanTypeCombo = new JComboBox<>(new String[]{"Crawl and audit", "Crawl only", "Audit only"});
        this.auditConfigurationCombo = new JComboBox<>(new String[]{"Active audit checks", "Passive audit checks"});
        this.scanLaunchBcheckModel = new DefaultListModel<>();
        this.scanLaunchBcheckList = new JList<>(scanLaunchBcheckModel);
        this.scanLaunchStatusArea = buildReadOnlyTextArea(
                "Use this panel to start Burp scans from AI Bridge where Montoya exposes the capability."
        );
        this.launchScanButton = new JButton("Run Scan");
        this.useCurrentTargetButton = new JButton("Set Current Target");
        this.addScanBcheckButton = new JButton("Add BCheck");
        this.removeScanBcheckButton = new JButton("Remove Selected");
        this.clearScanBcheckButton = new JButton("Clear");
        this.syncCollaboratorButton = new JButton("Sync Client");
        this.rotateCollaboratorButton = new JButton("Rotate Client");
        this.copyCollaboratorPayloadButton = new JButton("Copy Payload");
        this.analyzeRecentScanButton = new JButton("Review Recent Findings");
        this.analyzeCurrentTargetScanButton = new JButton("Review This Target");
        this.copyNewScanHandoffButton = new JButton("Copy Full Workflow");
        this.latestDetailedWorkflowText = this.newScanHandoffArea.getText();
        this.latestRecommendedScanBchecks = new ArrayList<>();
        this.latestPotentialFindings = new ArrayList<>();
        this.timeBudgetCombo.setSelectedItem("Balanced");
        this.timeBudgetCombo.setFont(FORM_FONT);
        this.timeBudgetCombo.setToolTipText("Control whether the bridge prioritizes speed, balanced reasoning, or deeper local-model passes.");
        this.currentAssessmentRequest = null;
        this.currentJobId = "";
        this.resultsTabs = buildResultsTabs();
        this.investigationTabs = new JTabbedPane();
        this.investigationTabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        this.investigationWorkspaces = new LinkedHashMap<>();
        this.investigationHintArea = buildReadOnlyTextArea(DEFAULT_INVESTIGATION_HELP);
        this.investigationHintArea.setRows(2);
        this.investigationHintArea.setFont(FORM_FONT);
        this.investigationHintArea.setForeground(HELPER_COLOR);
        this.investigationHintArea.setOpaque(false);
        this.investigationHintArea.setBorder(new EmptyBorder(2, 4, 2, 4));
        this.reuseRepeaterInvestigationsCheckBox = new JCheckBox("Reuse matching Repeater investigations", true);
        this.activeInvestigationId = "";
        this.workspaceTabs = buildWorkspaceTabs();
        this.applyBurpSettingsButton.setEnabled(false);
        this.disableBurpSettingsButton.setEnabled(false);
        this.aiBridgeSettingsStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        this.saveSettingsButton.setEnabled(false);
        this.reloadSettingsButton.setEnabled(false);
        this.clearSettingsButton.setEnabled(false);
        this.jobWatchdogTimer = new Timer(5000, ignored -> maybeWarnAboutSlowJob());
        this.jobWatchdogTimer.setRepeats(true);
        this.jobWatchdogTimer.start();
        this.jobWatchdogActive = false;
        this.stuckWarningShown = false;
        this.lastJobUpdateAtMillis = 0L;
        mainPanel.add(buildHeader(), BorderLayout.NORTH);
        mainPanel.add(workspaceTabs, BorderLayout.CENTER);
        configureFeedbackControls();
        configureOperatorInputControls();
        applyDefaultReviewScope();
        updateScopeSummary();
        disableFeedback("Feedback becomes available after a single completed analysis.");
        setFollowUpEnabled(false);
        setFollowUpCancelEnabled(false);
    }

    public String endpointUrl() {
        return endpointField.getText().trim();
    }

    public String currentJobId() {
        return currentJobId == null ? "" : currentJobId;
    }

    public String activeInvestigationId() {
        return activeInvestigationId == null ? "" : activeInvestigationId;
    }

    public boolean reuseRepeaterInvestigations() {
        return reuseRepeaterInvestigationsCheckBox.isSelected();
    }

    public String privacyMode() {
        return "OFF";
    }

    public String selectedProfile() {
        return "";
    }

    public String selectedTimeBudgetLabel() {
        Object value = timeBudgetCombo.getSelectedItem();
        if (value == null) {
            return "Balanced";
        }
        String label = value.toString().trim();
        return label.isBlank() ? "Balanced" : label;
    }

    public String selectedTimeBudgetAnnotation() {
        return switch (selectedTimeBudgetLabel().toLowerCase()) {
            case "fast" -> "time_budget_fast";
            case "deep" -> "time_budget_deep";
            default -> "time_budget_balanced";
        };
    }

    public Map<String, String> currentAnswers() {
        Map<String, String> answers = new LinkedHashMap<>();
        for (Map.Entry<String, JTextField> entry : questionInputs.entrySet()) {
            String value = entry.getValue().getText().trim();
            if (!value.isBlank()) {
                answers.put(entry.getKey(), value);
            }
        }
        return answers;
    }

    public Map<String, String> operatorAnswersForSubmission() {
        Map<String, String> answers = new LinkedHashMap<>(currentAnswers());
        String suggestionFollowUp = suggestionFollowUpText();
        if (!suggestionFollowUp.isBlank()) {
            answers.put(SUGGESTION_FOLLOW_UP_KEY, suggestionFollowUp);
        }
        return answers;
    }

    public String toolHelpText() {
        String detected = detectedToolInventoryArea.getText().trim();
        String manual = toolHelpArea.getText().trim();
        if (detected.isBlank()) {
            return manual;
        }
        if (manual.isBlank()) {
            return detected;
        }
        return detected + System.lineSeparator() + System.lineSeparator() + manual;
    }

    public String scopeIncludesText() {
        return scopeIncludesArea.getText().trim();
    }

    public String scopeExcludesText() {
        return scopeExcludesArea.getText().trim();
    }

    public String rateLimitText() {
        return rateLimitField.getText().trim();
    }

    public String maxConcurrencyText() {
        return maxConcurrencyField.getText().trim();
    }

    public String customHeadersText() {
        return customHeadersArea.getText().trim();
    }

    public String programPolicyText() {
        return programPolicyArea.getText().trim();
    }

    public String toolResultsText() {
        return toolResultsArea.getText().trim();
    }

    public String burpConfigExportText() {
        return burpConfigExportArea.getText().trim();
    }

    public String burpScreenshotAuditText() {
        return burpScreenshotAuditArea.getText().trim();
    }

    public String savedBurpToolsText() {
        return savedLoadedBurpToolsArea.getText().trim();
    }

    public String savedProgramPolicyText() {
        return savedProgramPolicyArea.getText().trim();
    }

    public String savedProgramScreenshotText() {
        return savedProgramScreenshotArea.getText().trim();
    }

    public boolean autoUseSavedSettings() {
        return autoUseSavedSettingsCheckBox.isSelected();
    }

    public String effectiveProgramPolicyText() {
        return joinTextBlocks(
                savedProgramPolicyText(),
                programPolicyText()
        );
    }

    public String effectiveBurpConfigExportText() {
        return autoUseSavedSettings() ? burpConfigExportText() : "";
    }

    public String effectiveBurpScreenshotAuditText() {
        if (!autoUseSavedSettings()) {
            return "";
        }
        return joinLabeledTextBlocks(
                "Saved Burp global settings screenshots and notes",
                burpScreenshotAuditText(),
                "Saved bug bounty program screenshots and notes",
                savedProgramScreenshotText()
        );
    }

    public String responseDeltaText() {
        return responseDeltaArea.getText().trim();
    }

    public String bappFindingsText() {
        return bappFindingsArea.getText().trim();
    }

    public String loggerEvidenceText() {
        return loggerEvidenceArea.getText().trim();
    }

    public String collaboratorEvidenceText() {
        return collaboratorEvidenceArea.getText().trim();
    }

    public String suggestionFollowUpText() {
        return suggestionFollowUpArea.getText().trim();
    }

    public List<String> reviewScopeIncludeClasses() {
        List<String> included = new ArrayList<>(ALL_REVIEW_CLASSES);
        included.removeAll(reviewScopeExcludeClasses());
        return included;
    }

    public List<String> reviewScopeExcludeClasses() {
        List<String> excluded = new ArrayList<>();
        for (int index = 0; index < skippedScopeModel.size(); index++) {
            excluded.add(skippedScopeModel.getElementAt(index));
        }
        return excluded;
    }

    public List<String> evidenceTimelineEntries() {
        return List.copyOf(evidenceTimelineEntries);
    }

    public void showInvestigationQueued(String sessionId, String title, AssessmentRequest request, boolean reusedSession) {
        SwingUtilities.invokeLater(() -> {
            InvestigationWorkspace workspace = ensureInvestigationWorkspace(sessionId, title);
            setInvestigationFollowUpRunning(workspace, false);
            workspace.request = request == null ? null : request.copy();
            workspace.baselineRequest = safeText(request == null ? "" : request.getRawRequest());
            workspace.requestArea.setText(workspace.baselineRequest);
            workspace.requestArea.setCaretPosition(0);
            workspace.responseArea.setText(safeText(request == null ? "" : request.getRawResponse()));
            workspace.responseArea.setCaretPosition(0);
            workspace.contextArea.setText(buildInvestigationContext(request));
            workspace.contextArea.setCaretPosition(0);
            workspace.exactChangeArea.setText("Awaiting the first AI advisory for this investigation.");
            workspace.exactChangeArea.setCaretPosition(0);
            workspace.statusLabel.setText(
                    reusedSession
                            ? "Reused this investigation for the latest Burp request."
                            : "New investigation opened from the selected Burp item."
            );
            appendInvestigationTranscript(
                    workspace,
                    "system",
                    (reusedSession ? "Reused" : "Opened") + " "
                            + requestOriginLabel(request)
                            + " for "
                            + safeText(request == null ? "" : request.getTargetUrl())
            );
            appendNotebookEntry(
                    workspace,
                    "opened",
                    reusedSession ? "Investigation reused" : "Investigation opened",
                    requestOriginLabel(request) + " for " + safeText(request == null ? "" : request.getTargetUrl())
            );
            refreshInvestigationNotebook(workspace);
            selectInvestigation(sessionId);
        });
    }

    public void showInvestigationProgress(String sessionId, AssessmentRequest request, AnalysisJobStatus status) {
        SwingUtilities.invokeLater(() -> {
            InvestigationWorkspace workspace = ensureInvestigationWorkspace(sessionId, fallbackInvestigationTitle(request));
            workspace.request = request == null ? null : request.copy();
            workspace.contextArea.setText(buildInvestigationContext(request));
            workspace.contextArea.setCaretPosition(0);
            workspace.exactChangeArea.setText("Analysis in progress. AI Bridge will summarize the next exact request changes here when ready.");
            workspace.exactChangeArea.setCaretPosition(0);
            workspace.statusLabel.setText(statusLabelText(status));
            refreshInvestigationNotebook(workspace);
        });
    }

    public void showInvestigationFollowUpSubmitting(String sessionId) {
        SwingUtilities.invokeLater(() -> {
            InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
            if (workspace == null) {
                return;
            }
            setInvestigationFollowUpRunning(workspace, true);
            workspace.statusLabel.setText("Submitting this follow-up to AI Bridge...");
            refreshInvestigationNotebook(workspace);
        });
    }

    public void showInvestigationResult(String sessionId, AssessmentRequest request, AdvisoryResponse response) {
        SwingUtilities.invokeLater(() -> {
            InvestigationWorkspace workspace = ensureInvestigationWorkspace(sessionId, fallbackInvestigationTitle(request));
            setInvestigationFollowUpRunning(workspace, false);
            workspace.request = request == null ? null : request.copy();
            workspace.response = response;
            workspace.baselineRequest = safeText(request == null ? workspace.baselineRequest : request.getRawRequest());
            workspace.requestArea.setText(workspace.baselineRequest);
            workspace.requestArea.setCaretPosition(0);
            workspace.responseArea.setText(safeText(request == null ? "" : request.getRawResponse()));
            workspace.responseArea.setCaretPosition(0);
            workspace.contextArea.setText(buildInvestigationContext(request));
            workspace.contextArea.setCaretPosition(0);
            workspace.exactChangeArea.setText(buildExactChangeSummary(response));
            workspace.exactChangeArea.setCaretPosition(0);
            workspace.statusLabel.setText("AI response ready. Edit the draft request or ask for the next exact change.");
            if (workspace.chatInputArea.getText().isBlank()) {
                workspace.chatInputArea.setText(defaultInvestigationPrompt(request, response));
            }
            appendInvestigationTranscript(workspace, "assistant", buildInvestigationReply(response));
            appendNotebookEntry(
                    workspace,
                    "assistant_guidance",
                    "AI guidance update",
                    buildNotebookAssistantSummary(response, workspace.exactChangeArea.getText())
            );
            refreshInvestigationNotebook(workspace);
            selectInvestigation(sessionId);
        });
    }

    public void showInvestigationError(String sessionId, String message) {
        SwingUtilities.invokeLater(() -> {
            InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
            if (workspace == null) {
                return;
            }
            setInvestigationFollowUpRunning(workspace, false);
            workspace.statusLabel.setText("AI Bridge request failed for this investigation.");
            workspace.exactChangeArea.setText("No exact request changes available because the AI Bridge request failed.");
            workspace.exactChangeArea.setCaretPosition(0);
            appendInvestigationTranscript(
                    workspace,
                    "system",
                    message == null || message.isBlank() ? "The AI Bridge request failed." : message
            );
            appendNotebookEntry(
                    workspace,
                    "error",
                    "Investigation error",
                    message == null || message.isBlank() ? "The AI Bridge request failed." : message
            );
            refreshInvestigationNotebook(workspace);
            selectInvestigation(sessionId);
        });
    }

    public void showInvestigationFollowUpCanceled(String sessionId, String message) {
        SwingUtilities.invokeLater(() -> {
            InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
            if (workspace == null) {
                return;
            }
            setInvestigationFollowUpRunning(workspace, false);
            workspace.statusLabel.setText(
                    message == null || message.isBlank()
                            ? "AI follow-up stopped locally for this investigation."
                            : message
            );
            refreshInvestigationNotebook(workspace);
        });
    }

    public void showPendingAssessment(AssessmentRequest request) {
        SwingUtilities.invokeLater(() -> {
            ensureResultsVisible();
            currentAssessmentRequest = request;
            currentJobId = "";
            startJobWatchdog();
            updateReportLinks("");
            String sourceLabel = requestOriginLabel(request);
            setStatus("Submitting " + sourceLabel + " to local AI...", new Color(0x0F6CBD));
            targetLabel.setText(request.getTargetUrl());
            methodLabel.setText(requestMethodLabel(request));
            updatedLabel.setText(timestampNow());
            providerRouteField.setText(buildPendingProviderRoute(request));
            estimatedDurationField.setText("Estimating...");
            complexityField.setText("Estimating...");
            resetChipPanel(findingChipsPanel, "Awaiting findings");
            resetChipPanel(confidenceChipsPanel, "Awaiting confidence");
            primaryNextActionField.setText("Awaiting recommendation");
            analysisArea.setText("The " + sourceLabel + " was submitted to the local FastAPI bridge. Waiting for the analysis job to start.");
            requestPlanArea.setText("Waiting for a compact " + sourceLabel.toLowerCase() + " plan.");
            vulnerabilitiesArea.setText("Waiting for vulnerability triage.");
            kaliToolsArea.setText("Waiting for Kali tool recommendations.");
            kaliCommandsArea.setText("Waiting for Kali command templates.");
            payloadListsArea.setText("Waiting for payload starter lists.");
            bcheckRecommendationsArea.setText("Waiting for upstream BCheck recommendations.");
            projectReadinessField.setText("Scoring readiness...");
            projectReadinessArea.setText("Waiting for project readiness checks.");
            burpActionChecklistArea.setText("Waiting for a Burp action checklist.");
            impactPathsArea.setText("Waiting for impact-oriented escalation paths.");
            burpSettingsArea.setText("Waiting for Burp settings recommendations.");
            sourceLinksArea.setText("Waiting for supporting source links.");
            suggestionQueueArea.setText("Waiting for a manual suggestion queue.");
            confidenceArea.setText("Waiting for confidence scoring.");
            historyCorrelationArea.setText("Waiting for history correlation.");
            confirmationPlaybooksArea.setText("Waiting for confirmation guidance.");
            reasoningSummaryArea.setText("Waiting for the stored reasoning summary.");
            phaseHistoryArea.setText("Waiting for phase history snapshots.");
            scanBridgeGuidanceArea.setText(pendingScanBridgeGuidance(request));
            refreshScanWorkflowText(null, request);
            showVisionReviewStatus("Awaiting advisory response for screenshot review status.");
            latestRecommendedScanBchecks = new ArrayList<>();
            latestPotentialFindings = new ArrayList<>();
            refreshScanLaunchBchecks(List.of());
            nucleiTagsField.setText("Awaiting recommendation");
            seclistsPathField.setText("Awaiting recommendation");
            resetInteractionState(true);
            renderQuestionInputs(List.of());
            disableFeedback("Feedback will unlock after this job completes.");
            setFollowUpEnabled(false);
            setFollowUpStatus(
                    "Awaiting the first advisory response before another AI follow-up can be submitted.",
                    "Wait for the advisory response, then draft or submit a suggestion-specific follow-up."
            );
            setFollowUpCancelEnabled(false);
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
        });
    }

    public void showBatchQueued(int totalRequests) {
        SwingUtilities.invokeLater(() -> {
            ensureResultsVisible();
            currentJobId = "";
            startJobWatchdog();
            updateReportLinks("");
            setStatus("Batch queued.", new Color(0x0F6CBD));
            targetLabel.setText(totalRequests + " requests selected");
            methodLabel.setText("BATCH");
            updatedLabel.setText(timestampNow());
            providerRouteField.setText("Context: Burp MCP | Reasoning: local AI | Time budget: " + selectedTimeBudgetLabel() + " | Batch mode");
            estimatedDurationField.setText("Per-request ETA");
            complexityField.setText("Batch mode");
            resetChipPanel(findingChipsPanel, "Batch summary pending");
            resetChipPanel(confidenceChipsPanel, "Batch summary pending");
            primaryNextActionField.setText("Batch mode summary pending");
            analysisArea.setText("Submitting a batch of " + totalRequests + " requests. They will be analyzed one by one.");
            requestPlanArea.setText("Batch mode does not create a single request plan while queued.");
            vulnerabilitiesArea.setText("Waiting for grouped batch results.");
            kaliToolsArea.setText("Batch mode does not show per-request tool recommendations while queued.");
            kaliCommandsArea.setText("Batch mode does not show per-request command templates while queued.");
            payloadListsArea.setText("Batch mode does not show per-request payload lists while queued.");
            bcheckRecommendationsArea.setText("Batch mode does not show per-request BCheck guidance while queued.");
            projectReadinessField.setText("Batch mode");
            projectReadinessArea.setText("Batch mode does not show a single readiness score while queued.");
            burpActionChecklistArea.setText("Batch mode does not show a single Burp action checklist while queued.");
            impactPathsArea.setText("Batch mode does not show per-request impact paths while queued.");
            burpSettingsArea.setText("Batch mode does not show per-request Burp settings guidance while queued.");
            sourceLinksArea.setText("Waiting for grouped source links.");
            suggestionQueueArea.setText("Batch mode will summarize after completion.");
            confidenceArea.setText("Batch mode does not show per-request confidence while queued.");
            historyCorrelationArea.setText("Batch mode correlation will be available in each completed report.");
            confirmationPlaybooksArea.setText("Batch mode confirmation playbooks are available in per-request reports.");
            reasoningSummaryArea.setText("Batch mode does not produce one shared reasoning summary.");
            phaseHistoryArea.setText("Use a completed single-request job to inspect stored phase history.");
            scanBridgeGuidanceArea.setText("Batch mode does not produce a single scan confirmation plan.");
            newScanHandoffArea.setText("Batch mode does not produce a single Burp workflow handoff.");
            latestDetailedWorkflowText = newScanHandoffArea.getText();
            latestRecommendedScanBchecks = new ArrayList<>();
            latestPotentialFindings = new ArrayList<>();
            refreshScanLaunchBchecks(List.of());
            nucleiTagsField.setText("Awaiting batch summary");
            seclistsPathField.setText("Awaiting batch summary");
            resetInteractionState(true);
            renderQuestionInputs(List.of());
            disableFeedback("Feedback is only available for single completed analyses, not batch mode.");
            setFollowUpEnabled(false);
            setFollowUpStatus("AI follow-up is disabled in batch mode.", "AI follow-up is disabled in batch mode.");
            setFollowUpCancelEnabled(false);
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
        });
    }

    public void showBatchProgress(int currentIndex, int totalRequests, AssessmentRequest request, AnalysisJobStatus status) {
        SwingUtilities.invokeLater(() -> {
            ensureResultsVisible();
            currentJobId = "";
            refreshJobWatchdog();
            updateReportLinks("");
            Color color = switch (status.getStatus()) {
                case "completed" -> new Color(0x2D7D46);
                case "failed" -> new Color(0xB42318);
                default -> new Color(0x0F6CBD);
            };
            setStatus("Batch running: " + currentIndex + "/" + totalRequests, color);
            targetLabel.setText(request.getTargetUrl());
            methodLabel.setText(request.getHttpMethod());
            updatedLabel.setText(timestampNow());
            providerRouteField.setText(buildRunningProviderRoute(request, status));
            estimatedDurationField.setText(status.getEstimatedDuration());
            complexityField.setText("Batch item: " + status.getComplexity());
            resetChipPanel(findingChipsPanel, "Batch item running");
            resetChipPanel(confidenceChipsPanel, "Batch item running");
            primaryNextActionField.setText("Batch item in progress");
            analysisArea.setText(
                    "Batch item " + currentIndex + " of " + totalRequests + System.lineSeparator() + System.lineSeparator()
                            + buildProgressText(status)
            );
            requestPlanArea.setText("Batch mode groups request plans after completion.");
            vulnerabilitiesArea.setText("Collecting grouped results for the batch.");
            kaliToolsArea.setText("Batch mode groups results after completion.");
            kaliCommandsArea.setText("Batch mode groups results after completion.");
            payloadListsArea.setText("Batch mode groups results after completion.");
            bcheckRecommendationsArea.setText("Batch mode groups results after completion.");
            projectReadinessField.setText("Batch mode");
            projectReadinessArea.setText("Batch mode readiness should be reviewed per request after completion.");
            burpActionChecklistArea.setText("Batch mode Burp checklists should be reviewed per request after completion.");
            impactPathsArea.setText("Batch mode groups impact paths after completion.");
            burpSettingsArea.setText("Batch mode groups Burp settings guidance after completion.");
            sourceLinksArea.setText("Collecting grouped source links for the batch.");
            suggestionQueueArea.setText("Batch mode suggestion queue is summarized after completion.");
            confidenceArea.setText("Batch mode confidence is summarized per item in the exported reports.");
            historyCorrelationArea.setText("Batch correlation is available in exported reports for completed items.");
            confirmationPlaybooksArea.setText("Batch confirmation guidance is available in the exported reports.");
            reasoningSummaryArea.setText("Batch mode reasoning is tracked per completed request.");
            phaseHistoryArea.setText("Use a completed single-request job to inspect phase snapshots.");
            scanBridgeGuidanceArea.setText("Batch mode does not produce a single scan confirmation plan while jobs are running.");
            newScanHandoffArea.setText("Batch mode does not produce a single Burp workflow handoff while jobs are running.");
            latestDetailedWorkflowText = newScanHandoffArea.getText();
            showVisionReviewStatus("Batch mode does not run a single screenshot review status for the whole batch.");
            latestRecommendedScanBchecks = new ArrayList<>();
            latestPotentialFindings = new ArrayList<>();
            refreshScanLaunchBchecks(List.of());
            nucleiTagsField.setText("Awaiting batch summary");
            seclistsPathField.setText("Awaiting batch summary");
            renderQuestionInputs(List.of());
            disableFeedback("Feedback is only available for single completed analyses, not batch mode.");
            setFollowUpEnabled(false);
            setFollowUpStatus("AI follow-up is disabled in batch mode.", "AI follow-up is disabled in batch mode.");
            setFollowUpCancelEnabled(false);
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
        });
    }

    public void showBatchSummary(
            int totalRequests,
            int completedRequests,
            String summaryText,
            String groupedFindings,
            String combinedTags,
            String suggestedWordlist,
            List<String> followUpQuestions,
            String sourceLinksText
    ) {
        SwingUtilities.invokeLater(() -> {
            ensureResultsVisible();
            currentJobId = "";
            stopJobWatchdog();
            updateReportLinks("");
            setStatus("Batch complete.", new Color(0x2D7D46));
            targetLabel.setText(completedRequests + "/" + totalRequests + " requests analyzed");
            methodLabel.setText("BATCH");
            updatedLabel.setText(timestampNow());
            providerRouteField.setText("Context: Burp MCP | Reasoning: local AI | Time budget: " + selectedTimeBudgetLabel() + " | Batch summary ready");
            estimatedDurationField.setText("Use per request");
            complexityField.setText("Batch complete");
            refreshFindingChips(List.of(groupedFindings == null || groupedFindings.isBlank() ? "No grouped findings" : "Batch findings"));
            resetChipPanel(confidenceChipsPanel, "Use per-request reports");
            primaryNextActionField.setText("Use per-request reports for the next action.");
            analysisArea.setText(summaryText);
            requestPlanArea.setText("Use per-request reports to review the compact request plan for each request.");
            vulnerabilitiesArea.setText(groupedFindings);
            kaliToolsArea.setText("Use per-request reports to review the precise Kali tool recommendations.");
            kaliCommandsArea.setText("Use per-request reports to review the precise command templates.");
            payloadListsArea.setText("Use per-request reports to review the precise payload starter lists.");
            bcheckRecommendationsArea.setText("Use per-request reports to review the precise BCheck recommendations.");
            projectReadinessField.setText("Use reports");
            projectReadinessArea.setText("Use per-request reports to review project readiness checks.");
            burpActionChecklistArea.setText("Use per-request reports to review the Burp action checklist.");
            sourceLinksArea.setText(sourceLinksText == null || sourceLinksText.isBlank()
                    ? "No source links were collected for this batch."
                    : sourceLinksText);
            suggestionQueueArea.setText("Use the batch summary and per-request reports to work through the next manual checks one request at a time.");
            confidenceArea.setText("Batch mode groups findings by vuln class. Use per-request reports for confidence details.");
            historyCorrelationArea.setText("Export a completed request report from the matching job to review history correlation details.");
            confirmationPlaybooksArea.setText("Export a completed request report from the matching job to review confirmation playbooks.");
            reasoningSummaryArea.setText("Batch mode stores reasoning per completed request, not in one combined summary.");
            phaseHistoryArea.setText("Open a completed single-request job to inspect phase snapshots.");
            scanBridgeGuidanceArea.setText("Use single-request or selected-issue analysis to build a launchable confirmation plan.");
            newScanHandoffArea.setText("Use a single request or selected issue if you want a Burp workflow handoff.");
            latestDetailedWorkflowText = newScanHandoffArea.getText();
            showVisionReviewStatus("Use per-request advisory output to review screenshot vision status.");
            latestRecommendedScanBchecks = new ArrayList<>();
            latestPotentialFindings = new ArrayList<>();
            refreshScanLaunchBchecks(List.of());
            nucleiTagsField.setText(combinedTags == null || combinedTags.isBlank() ? "No combined tags" : combinedTags);
            seclistsPathField.setText(suggestedWordlist == null || suggestedWordlist.isBlank()
                    ? "No single recommended path"
                    : suggestedWordlist);
            resetInteractionState(true);
            renderQuestionInputs(followUpQuestions == null ? List.of() : followUpQuestions);
            disableFeedback("Feedback is only available for single completed analyses, not batch mode.");
            setFollowUpEnabled(false);
            setFollowUpStatus("AI follow-up is disabled in batch mode.", "AI follow-up is disabled in batch mode.");
            setFollowUpCancelEnabled(false);
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
        });
    }

    public void showJobProgress(AssessmentRequest request, AnalysisJobStatus status) {
        SwingUtilities.invokeLater(() -> {
            ensureResultsVisible();
            currentJobId = status.getJobId();
            refreshJobWatchdog();
            updateReportLinks(currentJobId);
            Color color = switch (status.getStatus()) {
                case "completed" -> new Color(0x2D7D46);
                case "failed" -> new Color(0xB42318);
                default -> new Color(0x0F6CBD);
            };
            setStatus(statusLabelText(status), color);
            targetLabel.setText(request.getTargetUrl());
            methodLabel.setText(request.getHttpMethod());
            updatedLabel.setText(timestampNow());
            providerRouteField.setText(buildRunningProviderRoute(request, status));
            estimatedDurationField.setText(status.getEstimatedDuration());
            complexityField.setText(status.getComplexity());
            resetChipPanel(findingChipsPanel, "Awaiting findings");
            resetChipPanel(confidenceChipsPanel, "Awaiting confidence");
            primaryNextActionField.setText("Awaiting recommendation");
            analysisArea.setText(buildProgressText(status));
            requestPlanArea.setText("Waiting for the compact request plan.");
            vulnerabilitiesArea.setText("Waiting for final advisory output.");
            kaliToolsArea.setText("Waiting for Kali tool recommendations.");
            kaliCommandsArea.setText("Waiting for Kali command templates.");
            payloadListsArea.setText("Waiting for payload starter lists.");
            bcheckRecommendationsArea.setText("Waiting for upstream BCheck recommendations.");
            projectReadinessField.setText("Scoring readiness...");
            projectReadinessArea.setText("Waiting for project readiness checks.");
            burpActionChecklistArea.setText("Waiting for Burp action checklist guidance.");
            sourceLinksArea.setText("Waiting for supporting source links.");
            suggestionQueueArea.setText("Suggestion queue will appear when the advisory completes.");
            confidenceArea.setText("Confidence scoring will appear when the advisory completes.");
            historyCorrelationArea.setText("History correlation will appear when the advisory completes.");
            confirmationPlaybooksArea.setText("Confirmation guidance will appear when the advisory completes.");
            reasoningSummaryArea.setText("Loading stored reasoning summary for the active job.");
            phaseHistoryArea.setText("Loading phase history snapshots for the active job.");
            scanBridgeGuidanceArea.setText(pendingScanBridgeGuidance(request));
            refreshScanWorkflowText(null, request);
            showVisionReviewStatus("Screenshot review is running with the current advisory job when applicable.");
            latestRecommendedScanBchecks = new ArrayList<>();
            latestPotentialFindings = new ArrayList<>();
            refreshScanLaunchBchecks(List.of());
            nucleiTagsField.setText("Awaiting recommendation");
            seclistsPathField.setText("Awaiting recommendation");
            disableFeedback("Feedback will unlock after this job completes.");
            if (requestHasFollowUpContext(request)) {
                restoreOperatorInputs(request);
                setFollowUpStatus(
                        "Follow-up analysis is running with your latest answers, program context, and shared results.",
                        "The latest suggestion follow-up is processing. You can keep drafting while it runs."
                );
                setFollowUpEnabled(true);
                setFollowUpSubmitButtonsEnabled(false);
                setFollowUpCancelEnabled(true);
            } else {
                setFollowUpEnabled(false);
                setFollowUpSubmitButtonsEnabled(false);
                setFollowUpCancelEnabled(false);
                setFollowUpStatus(
                        "Follow-up analysis is waiting for the current job to finish.",
                        "No suggestion follow-up is running yet."
                );
            }
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
        });
    }

    public void updateResults(AdvisoryResponse response, AssessmentRequest request) {
        SwingUtilities.invokeLater(() -> {
            ensureResultsVisible();
            currentAssessmentRequest = request;
            stopJobWatchdog();
            updateReportLinks(currentJobId);
            setStatus("Local AI response ready for " + requestOriginLabel(request) + ".", new Color(0x2D7D46));
            targetLabel.setText(request.getTargetUrl());
            methodLabel.setText(requestMethodLabel(request));
            updatedLabel.setText(timestampNow());
            providerRouteField.setText(buildCompletedProviderRoute(response, request));
            refreshFindingChips(response.getPotentialVulnerabilities());
            refreshConfidenceChips(response.getConfidenceByClass());
            primaryNextActionField.setText(response.getPrimaryNextAction());
            toolAvailabilityField.setText(response.getToolAvailabilitySummary().isBlank()
                    ? toolInventoryStatusLabel.getText()
                    : response.getToolAvailabilitySummary());
            projectReadinessField.setText(response.getProjectReadinessSummary());
            analysisArea.setText(operatorVisibleAnalysis(response.getAnalysis()));
            requestPlanArea.setText(formatBulletList(
                    response.getRequestPlan(),
                    "No compact request plan was returned."
            ));
            vulnerabilitiesArea.setText(formatBulletList(
                    response.getPotentialVulnerabilities(),
                    "No potential vulnerabilities were listed."
            ));
            kaliToolsArea.setText(formatBulletList(
                    response.getManualTooling(),
                    "No Kali tool recommendations were returned."
            ));
            kaliCommandsArea.setText(formatBulletList(
                    response.getManualCommands(),
                    "No Kali command templates were returned."
            ));
            payloadListsArea.setText(formatBulletList(
                    response.getPayloadRecommendations(),
                    "No payload starter lists were returned."
            ));
            bcheckRecommendationsArea.setText(formatBulletList(
                    response.getBcheckRecommendations(),
                    "No BCheck recommendations were returned."
            ));
            projectReadinessArea.setText(formatBulletList(
                    response.getProjectReadinessChecks(),
                    "No project readiness checks were returned."
            ));
            burpActionChecklistArea.setText(formatBulletList(
                    response.getBurpActionChecklist(),
                    "No Burp action checklist was returned."
            ));
            impactPathsArea.setText(formatBulletList(
                    response.getImpactPaths(),
                    "No impact-bearing escalation paths were returned."
            ));
            burpSettingsArea.setText(formatBulletList(
                    response.getBurpSettingsRecommendations(),
                    "No Burp settings recommendations were returned."
            ));
            sourceLinksArea.setText(formatSourceLinks(response.getSourceLinks()));
            suggestionQueueArea.setText(formatBulletList(
                    response.getSuggestionQueue(),
                    "No manual suggestion queue was returned."
            ));
            confidenceArea.setText(formatBulletList(
                    response.getConfidenceByClass(),
                    "No confidence scoring was returned."
            ));
            historyCorrelationArea.setText(formatBulletList(
                    response.getHistoryCorrelation(),
                    "No history correlation notes were returned."
            ));
            confirmationPlaybooksArea.setText(formatBulletList(
                    response.getConfirmationPlaybooks(),
                    "No confirmation playbooks were returned."
            ));
            showVisionReviewStatus(response.getBurpScreenshotReviewStatus());
            scanBridgeGuidanceArea.setText(buildScanBridgeGuidance(response, request));
            scanBridgeGuidanceArea.setCaretPosition(0);
            refreshScanWorkflowText(response, request);
            latestRecommendedScanBchecks = new ArrayList<>(response.getBcheckRecommendations());
            latestPotentialFindings = new ArrayList<>(response.getPotentialVulnerabilities());
            refreshScanLaunchBchecks(response.getBcheckRecommendations());
            nucleiTagsField.setText(response.getNucleiTags());
            seclistsPathField.setText(response.getSeclistsPath());
            renderQuestionInputs(response.getQuestionsForUser());
            enableFeedback("Latest job: " + (currentJobId == null || currentJobId.isBlank() ? "<unknown>" : currentJobId));
            boolean hadFollowUpContext = requestHasFollowUpContext(request);
            if (!hadFollowUpContext) {
                setFollowUpStatus(
                        "AI response ready. Type answers, a suggestion follow-up, program context, or shared tool results, then submit another AI follow-up if needed.",
                        "AI response ready. You can refine a queue item here and send another follow-up if needed."
                );
            } else {
                setFollowUpStatus(
                        "AI received your latest answers. Update them and submit again if you want another follow-up.",
                        "The last suggestion follow-up completed. Edit the request and resubmit if you want a narrower answer."
                );
            }
            restoreOperatorInputs(request);
            setFollowUpEnabled(true);
            setFollowUpSubmitButtonsEnabled(true);
            setFollowUpCancelEnabled(false);
            selectBestResultTab(response, request, hadFollowUpContext);
        });
    }

    public void showReasoningLoading(String jobId) {
        SwingUtilities.invokeLater(() -> {
            String normalizedJobId = jobId == null || jobId.isBlank() ? "<active job>" : jobId;
            reasoningSummaryArea.setText("Loading stored reasoning summary for " + normalizedJobId + "...");
            phaseHistoryArea.setText("Loading phase history snapshots for " + normalizedJobId + "...");
        });
    }

    public void updateReasoningSummary(AnalysisReasoningResponse reasoning, PhaseHistoryResponse phaseHistory) {
        SwingUtilities.invokeLater(() -> {
            reasoningSummaryArea.setText(formatReasoningSummary(reasoning));
            reasoningSummaryArea.setCaretPosition(0);
            phaseHistoryArea.setText(formatPhaseHistory(phaseHistory));
            phaseHistoryArea.setCaretPosition(0);
        });
    }

    public void showReasoningUnavailable(String message) {
        SwingUtilities.invokeLater(() -> {
            String normalized = message == null || message.isBlank()
                    ? "Stored reasoning data is not available for the current job."
                    : message;
            reasoningSummaryArea.setText(normalized);
            phaseHistoryArea.setText(normalized);
        });
    }

    public void showError(String message) {
        SwingUtilities.invokeLater(() -> {
            ensureResultsVisible();
            currentAssessmentRequest = null;
            stopJobWatchdog();
            updateReportLinks("");
            setStatus("Bridge request failed.", new Color(0xB42318));
            updatedLabel.setText(timestampNow());
            providerRouteField.setText("Context: Burp MCP | Reasoning: local AI | Time budget: " + selectedTimeBudgetLabel() + " | Request failed");
            estimatedDurationField.setText("Unavailable");
            complexityField.setText("Unavailable");
            resetChipPanel(findingChipsPanel, "Unavailable");
            resetChipPanel(confidenceChipsPanel, "Unavailable");
            primaryNextActionField.setText("Unavailable");
            analysisArea.setText(message == null || message.isBlank()
                    ? "The bridge request failed for an unknown reason."
                    : message);
            requestPlanArea.setText("Unavailable");
            vulnerabilitiesArea.setText("No advisory output was returned.");
            kaliToolsArea.setText("Unavailable");
            kaliCommandsArea.setText("Unavailable");
            payloadListsArea.setText("Unavailable");
            bcheckRecommendationsArea.setText("Unavailable");
            projectReadinessField.setText("Unavailable");
            projectReadinessArea.setText("Unavailable");
            burpActionChecklistArea.setText("Unavailable");
            impactPathsArea.setText("Unavailable");
            burpSettingsArea.setText("Unavailable");
            showVisionReviewStatus("Unavailable because the advisory request failed.");
            sourceLinksArea.setText("Unavailable");
            suggestionQueueArea.setText("Unavailable");
            confidenceArea.setText("Unavailable");
            historyCorrelationArea.setText("Unavailable");
            confirmationPlaybooksArea.setText("Unavailable");
            reasoningSummaryArea.setText("Unavailable");
            phaseHistoryArea.setText("Unavailable");
            scanBridgeGuidanceArea.setText("Unavailable");
            newScanHandoffArea.setText("Unavailable");
            latestDetailedWorkflowText = "Unavailable";
            latestRecommendedScanBchecks = new ArrayList<>();
            latestPotentialFindings = new ArrayList<>();
            refreshScanLaunchBchecks(List.of());
            nucleiTagsField.setText("Unavailable");
            seclistsPathField.setText("Unavailable");
            renderQuestionInputs(List.of());
            disableFeedback("Feedback is unavailable because the latest job did not complete successfully.");
            setFollowUpEnabled(false);
            setFollowUpStatus(
                    "The follow-up request failed. Adjust your answers, program context, or shared tool results and submit again.",
                    "The follow-up request failed. Edit the suggestion request and resubmit."
            );
            setFollowUpCancelEnabled(false);
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
        });
    }

    public void setFeedbackSubmitter(BiConsumer<String, String> feedbackSubmitter) {
        this.feedbackSubmitter = feedbackSubmitter;
    }

    public void setFollowUpSubmitter(Runnable followUpSubmitter) {
        this.followUpSubmitter = followUpSubmitter;
    }

    public void setFollowUpCanceler(Runnable followUpCanceler) {
        this.followUpCanceler = followUpCanceler;
    }

    public void setInvestigationChatSubmitter(BiConsumer<String, String> investigationChatSubmitter) {
        this.investigationChatSubmitter = investigationChatSubmitter;
    }

    public void setInvestigationSelectionListener(Consumer<String> investigationSelectionListener) {
        this.investigationSelectionListener = investigationSelectionListener;
    }

    public void setInvestigationRepeaterSender(Consumer<String> investigationRepeaterSender) {
        this.investigationRepeaterSender = investigationRepeaterSender;
    }

    public void setInvestigationRenameListener(BiConsumer<String, String> investigationRenameListener) {
        this.investigationRenameListener = investigationRenameListener;
    }

    public void setInvestigationCloseListener(Consumer<String> investigationCloseListener) {
        this.investigationCloseListener = investigationCloseListener;
    }

    public void setRepeaterReuseSettingListener(Consumer<Boolean> repeaterReuseSettingListener) {
        this.repeaterReuseSettingListener = repeaterReuseSettingListener;
    }

    public void setToolInventoryRefresher(Runnable toolInventoryRefresher) {
        this.toolInventoryRefresher = toolInventoryRefresher;
    }

    public void setCollaboratorSyncer(Runnable collaboratorSyncer) {
        this.collaboratorSyncer = collaboratorSyncer;
    }

    public void setCollaboratorRotator(Runnable collaboratorRotator) {
        this.collaboratorRotator = collaboratorRotator;
    }

    public void setRecentScanAnalyzer(Runnable recentScanAnalyzer) {
        this.recentScanAnalyzer = recentScanAnalyzer;
    }

    public void setCurrentTargetScanAnalyzer(Runnable currentTargetScanAnalyzer) {
        this.currentTargetScanAnalyzer = currentTargetScanAnalyzer;
    }

    public void setBcheckCatalogOpener(Runnable bcheckCatalogOpener) {
        this.bcheckCatalogOpener = bcheckCatalogOpener;
    }

    public void setBurpSettingsApplier(Runnable burpSettingsApplier) {
        this.burpSettingsApplier = burpSettingsApplier;
        applyBurpSettingsButton.setEnabled(burpSettingsApplier != null);
    }

    public void setBurpSettingsDisabler(Runnable burpSettingsDisabler) {
        this.burpSettingsDisabler = burpSettingsDisabler;
    }

    public void setAiBridgeSettingsSaver(Runnable aiBridgeSettingsSaver) {
        this.aiBridgeSettingsSaver = aiBridgeSettingsSaver;
        saveSettingsButton.setEnabled(aiBridgeSettingsSaver != null);
    }

    public void setAiBridgeSettingsReloader(Runnable aiBridgeSettingsReloader) {
        this.aiBridgeSettingsReloader = aiBridgeSettingsReloader;
        reloadSettingsButton.setEnabled(aiBridgeSettingsReloader != null);
    }

    public void setAiBridgeSettingsClearer(Runnable aiBridgeSettingsClearer) {
        this.aiBridgeSettingsClearer = aiBridgeSettingsClearer;
        clearSettingsButton.setEnabled(aiBridgeSettingsClearer != null);
    }

    public void setScanLauncher(Consumer<ScanLaunchRequest> scanLauncher) {
        this.scanLauncher = scanLauncher;
    }

    public void setReuseRepeaterInvestigations(boolean enabled) {
        reuseRepeaterInvestigationsCheckBox.setSelected(enabled);
    }

    public String investigationRequestDraft(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        return workspace == null ? "" : workspace.requestArea.getText();
    }

    public String investigationResponseSnapshot(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        return workspace == null ? "" : workspace.responseArea.getText();
    }

    public String investigationChatTranscript(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        return workspace == null ? "" : workspace.chatTranscriptArea.getText();
    }

    public List<InvestigationTranscriptState> investigationTranscriptEntries(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        if (workspace == null) {
            return List.of();
        }
        ensureTranscriptEntriesLoaded(workspace);
        List<InvestigationTranscriptState> states = new ArrayList<>();
        for (InvestigationTranscriptEntry entry : workspace.transcriptEntries) {
            InvestigationTranscriptState state = new InvestigationTranscriptState();
            state.timestamp = entry.timestamp();
            state.speaker = entry.speakerLabel();
            state.message = entry.message();
            states.add(state);
        }
        return states;
    }

    public List<InvestigationNotebookEntryState> investigationNotebookEntries(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        if (workspace == null) {
            return List.of();
        }
        ensureNotebookEntriesLoaded(workspace);
        List<InvestigationNotebookEntryState> states = new ArrayList<>();
        for (InvestigationNotebookEntry entry : workspace.notebookEntries) {
            InvestigationNotebookEntryState state = new InvestigationNotebookEntryState();
            state.timestamp = entry.timestamp();
            state.kind = entry.kind();
            state.title = entry.title();
            state.details = entry.details();
            states.add(state);
        }
        return states;
    }

    public List<String> investigationWorkflowNotes(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        if (workspace == null) {
            return List.of();
        }

        ensureTranscriptEntriesLoaded(workspace);
        List<String> notes = new ArrayList<>();

        String status = compactSingleLine(workspace.statusLabel.getText(), 220);
        if (!status.isBlank()) {
            notes.add("Latest investigation status: " + status);
        }

        String exactChange = compactSingleLine(workspace.exactChangeArea.getText(), 360);
        if (!exactChange.isBlank()) {
            notes.add("Latest exact change summary: " + exactChange);
        }

        if (workspace.response != null) {
            String primaryNextAction = compactSingleLine(workspace.response.getPrimaryNextAction(), 260);
            if (!primaryNextAction.isBlank()) {
                notes.add("Last AI primary next action: " + primaryNextAction);
            }
        }

        int startIndex = Math.max(0, workspace.transcriptEntries.size() - 4);
        for (int index = startIndex; index < workspace.transcriptEntries.size(); index++) {
            InvestigationTranscriptEntry entry = workspace.transcriptEntries.get(index);
            notes.add(
                    "Transcript [" + entry.timestamp() + "] " + entry.speakerLabel() + ": "
                            + compactSingleLine(entry.message(), 420)
            );
        }
        return notes;
    }

    public String investigationCaseNotebookText(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        if (workspace == null) {
            return "";
        }
        ensureNotebookEntriesLoaded(workspace);
        return buildInvestigationCaseNotebook(workspace);
    }

    public String investigationTitle(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        return workspace == null ? "" : workspace.title;
    }

    public String investigationStatus(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        return workspace == null ? "" : safeText(workspace.statusLabel.getText());
    }

    public void restoreInvestigationSession(
            String sessionId,
            String title,
            AssessmentRequest request,
            String requestDraft,
            String chatTranscript,
            boolean select
    ) {
        restoreInvestigationSession(sessionId, title, request, requestDraft, chatTranscript, List.of(), List.of(), "", select);
    }

    public void restoreInvestigationSession(
            String sessionId,
            String title,
            AssessmentRequest request,
            String requestDraft,
            String chatTranscript,
            List<InvestigationTranscriptState> transcriptStates,
            List<InvestigationNotebookEntryState> notebookStates,
            String statusText,
            boolean select
    ) {
        SwingUtilities.invokeLater(() -> {
            InvestigationWorkspace workspace = ensureInvestigationWorkspace(sessionId, title);
            setInvestigationFollowUpRunning(workspace, false);
            workspace.title = title == null || title.isBlank() ? workspace.title : title;
            workspace.userRenamed = title != null && !title.isBlank();
            int tabIndex = investigationTabs.indexOfComponent(workspace.root);
            if (tabIndex >= 0) {
                investigationTabs.setTitleAt(tabIndex, workspace.title);
                investigationTabs.setTabComponentAt(tabIndex, buildInvestigationTabComponent(workspace));
            }
            workspace.request = request == null ? null : request.copy();
            workspace.baselineRequest = safeText(request == null ? "" : request.getRawRequest());
            workspace.requestArea.setText(requestDraft == null || requestDraft.isBlank() ? workspace.baselineRequest : requestDraft);
            workspace.requestArea.setCaretPosition(0);
            workspace.responseArea.setText(safeText(request == null ? "" : request.getRawResponse()));
            workspace.responseArea.setCaretPosition(0);
            workspace.contextArea.setText(buildInvestigationContext(request));
            workspace.contextArea.setCaretPosition(0);
            workspace.transcriptEntries.clear();
            workspace.transcriptEntries.addAll(toTranscriptEntries(transcriptStates));
            if (workspace.transcriptEntries.isEmpty()) {
                workspace.chatTranscriptArea.setText(safeText(chatTranscript));
                workspace.transcriptEntries.addAll(parseInvestigationTranscriptEntries(workspace.chatTranscriptArea.getText()));
            } else {
                workspace.chatTranscriptArea.setText(buildInvestigationTranscript(workspace.transcriptEntries));
            }
            workspace.chatTranscriptArea.setCaretPosition(0);
            workspace.notebookEntries.clear();
            workspace.notebookEntries.addAll(toNotebookEntries(notebookStates));
            workspace.exactChangeArea.setText(extractExactChangeSummaryFromTranscript(workspace.chatTranscriptArea.getText()));
            workspace.exactChangeArea.setCaretPosition(0);
            workspace.statusLabel.setText(
                    statusText == null || statusText.isBlank()
                            ? "Restored from the current Burp project."
                            : statusText
            );
            if (workspace.notebookEntries.isEmpty()) {
                rebuildLegacyNotebookEntries(workspace);
            }
            refreshInvestigationNotebook(workspace);
            if (select) {
                selectInvestigation(sessionId);
            }
        });
    }

    public void updateInvestigationTitle(String sessionId, String title) {
        SwingUtilities.invokeLater(() -> {
            InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
            if (workspace == null || workspace.userRenamed || title == null || title.isBlank()) {
                return;
            }
            workspace.title = title;
            int tabIndex = investigationTabs.indexOfComponent(workspace.root);
            if (tabIndex >= 0) {
                investigationTabs.setTitleAt(tabIndex, title);
                investigationTabs.setTabComponentAt(tabIndex, buildInvestigationTabComponent(workspace));
            }
        });
    }

    // Visible for package-local smoke tests.
    String selectedWorkspaceTabTitleForTest() {
        int selectedIndex = workspaceTabs.getSelectedIndex();
        return selectedIndex < 0 ? "" : workspaceTabs.getTitleAt(selectedIndex);
    }

    // Visible for package-local smoke tests.
    String selectedResultTabTitleForTest() {
        int selectedIndex = resultsTabs.getSelectedIndex();
        return selectedIndex < 0 ? "" : resultsTabs.getTitleAt(selectedIndex);
    }

    // Visible for package-local smoke tests.
    void setInvestigationChatInputForTest(String sessionId, String text) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        if (workspace != null) {
            workspace.chatInputArea.setText(text == null ? "" : text);
        }
    }

    // Visible for package-local smoke tests.
    void submitInvestigationChatForTest(String sessionId) {
        submitInvestigationChat(sessionId);
    }

    // Visible for package-local smoke tests.
    boolean investigationSubmitEnabledForTest(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        return workspace != null && workspace.submitButton.isEnabled();
    }

    // Visible for package-local smoke tests.
    String investigationStatusTextForTest(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        return workspace == null ? "" : workspace.statusLabel.getText();
    }

    public void showAiBridgeSettingsProject(String projectLabel) {
        SwingUtilities.invokeLater(() -> aiBridgeSettingsProjectField.setText(
                projectLabel == null || projectLabel.isBlank()
                        ? "Unknown Burp project"
                        : projectLabel
        ));
    }

    public void applyPersistedAiBridgeSettings(
            String burpConfigExportText,
            String burpScreenshotAuditText,
            String savedBurpToolsText,
            String savedProgramPolicyText,
            String savedProgramScreenshotText,
            boolean autoUseSavedSettings,
            String statusMessage
    ) {
        SwingUtilities.invokeLater(() -> {
            this.burpConfigExportArea.setText(burpConfigExportText == null ? "" : burpConfigExportText);
            this.burpScreenshotAuditArea.setText(burpScreenshotAuditText == null ? "" : burpScreenshotAuditText);
            this.savedLoadedBurpToolsArea.setText(savedBurpToolsText == null ? "" : savedBurpToolsText);
            this.savedProgramPolicyArea.setText(savedProgramPolicyText == null ? "" : savedProgramPolicyText);
            this.savedProgramScreenshotArea.setText(savedProgramScreenshotText == null ? "" : savedProgramScreenshotText);
            this.autoUseSavedSettingsCheckBox.setSelected(autoUseSavedSettings);
            aiBridgeSettingsStatusLabel.setText(
                    statusMessage == null || statusMessage.isBlank()
                            ? "AI-Bridge project settings loaded."
                            : statusMessage
            );
        });
    }

    public void showAiBridgeSettingsStatus(String statusMessage) {
        SwingUtilities.invokeLater(() -> aiBridgeSettingsStatusLabel.setText(
                statusMessage == null || statusMessage.isBlank()
                        ? "AI-Bridge project settings updated."
                        : statusMessage
        ));
    }

    public void showVisionReviewStatus(String statusMessage) {
        SwingUtilities.invokeLater(() -> {
            aiBridgeVisionStatusField.setText(
                    statusMessage == null || statusMessage.isBlank()
                            ? "No screenshot vision review has run yet."
                            : statusMessage
            );
            aiBridgeVisionStatusField.setCaretPosition(0);
        });
    }

    public void showFeedbackRecorded(String label) {
        SwingUtilities.invokeLater(() -> {
            feedbackStatusLabel.setText("Recorded feedback: " + label + ".");
            feedbackNotesField.setText("");
            feedbackNotesField.setEnabled(true);
            setFeedbackButtonsEnabled(true);
        });
    }

    public void showFeedbackError(String message) {
        SwingUtilities.invokeLater(() -> {
            feedbackStatusLabel.setText(
                    message == null || message.isBlank() ? "Unable to submit feedback." : "Feedback failed: " + message
            );
            feedbackNotesField.setEnabled(true);
            setFeedbackButtonsEnabled(true);
        });
    }

    public void showFollowUpSubmitting() {
        SwingUtilities.invokeLater(() -> {
            setFollowUpStatus(
                    "AI follow-up received. Processing your latest answers, suggestion context, privacy settings, BApp findings, and shared tool results...",
                    "AI follow-up received. Processing now. You can keep drafting while the current follow-up runs."
            );
            setFollowUpSubmitButtonsEnabled(false);
            setFollowUpCancelEnabled(true);
        });
    }

    public void showFollowUpSubmissionError(String message) {
        SwingUtilities.invokeLater(() -> {
            String text = message == null || message.isBlank()
                    ? "Unable to submit operator answers."
                    : "Follow-up submission failed: " + message;
            setFollowUpStatus(text, text);
            setFollowUpEnabled(true);
            setFollowUpSubmitButtonsEnabled(true);
            setFollowUpCancelEnabled(false);
        });
    }

    public void showFollowUpCanceled(String message) {
        SwingUtilities.invokeLater(() -> {
            String text = message == null || message.isBlank()
                    ? "Follow-up stopped locally. You can edit the request and submit again."
                    : message;
            setFollowUpStatus(text, text);
            setFollowUpEnabled(true);
            setFollowUpSubmitButtonsEnabled(true);
            setFollowUpCancelEnabled(false);
        });
    }

    public void showBackendHealthChecking(String message) {
        updateBackendHealthLabel(
                message == null || message.isBlank() ? "Checking backend health..." : message,
                HELPER_COLOR
        );
    }

    public void showBackendHealthy(String message) {
        updateBackendHealthLabel(
                message == null || message.isBlank() ? "Backend healthy." : message,
                new Color(0x2D7D46)
        );
    }

    public void showBackendHealthDeferred(String message) {
        updateBackendHealthLabel(
                message == null || message.isBlank() ? "Backend startup is still pending." : message,
                new Color(0xB54708)
        );
    }

    public void showBackendUnhealthy(String message) {
        updateBackendHealthLabel(
                message == null || message.isBlank() ? "Backend unavailable." : message,
                new Color(0xB42318)
        );
    }

    public void showToolInventoryLoading() {
        SwingUtilities.invokeLater(() -> {
            toolInventoryStatusLabel.setText("Refreshing Kali WSL tool inventory...");
            detectedToolInventoryArea.setText("Detecting installed and missing Kali WSL tools from the local bridge host.");
            refreshToolInventoryButton.setEnabled(false);
        });
    }

    public void showToolInventoryDeferred(String message) {
        SwingUtilities.invokeLater(() -> {
            String text = message == null || message.isBlank()
                    ? "Automatic Kali WSL tool inventory refresh is deferred until the backend is ready."
                    : message;
            toolInventoryStatusLabel.setText(text);
            detectedToolInventoryArea.setText(text);
            refreshToolInventoryButton.setEnabled(true);
        });
    }

    public void showToolInventory(KaliToolInventoryResponse response) {
        SwingUtilities.invokeLater(() -> {
            refreshToolInventoryButton.setEnabled(true);
            if (response == null) {
                toolInventoryStatusLabel.setText("No Kali tool inventory response was returned.");
                detectedToolInventoryArea.setText("No Kali tool inventory response was returned.");
                return;
            }

            StringBuilder builder = new StringBuilder();
            builder.append("Distro: ")
                    .append(response.getDistroName().isBlank() ? response.getDistro() : response.getDistroName())
                    .append(System.lineSeparator());
            builder.append("Installed: ").append(response.getInstalledCount()).append(System.lineSeparator());
            builder.append("Missing: ").append(response.getMissingCount()).append(System.lineSeparator());
            builder.append("Detected At: ").append(response.getDetectedAt()).append(System.lineSeparator()).append(System.lineSeparator());

            for (KaliToolInfo tool : response.getTools()) {
                builder.append("- ").append(tool.getName())
                        .append(tool.isInstalled() ? " [installed]" : " [missing]")
                        .append(System.lineSeparator());
                if (tool.isInstalled()) {
                    if (!tool.getVersion().isBlank()) {
                        builder.append("  Version: ").append(tool.getVersion()).append(System.lineSeparator());
                    }
                    if (!tool.getCommandPath().isBlank()) {
                        builder.append("  Path: ").append(tool.getCommandPath()).append(System.lineSeparator());
                    }
                    if (!tool.getHelpPreview().isBlank()) {
                        builder.append("  Help Preview:").append(System.lineSeparator())
                                .append(indentBlock(tool.getHelpPreview(), "    "))
                                .append(System.lineSeparator());
                    }
                } else {
                    builder.append("  Install: ").append(tool.getInstallHint()).append(System.lineSeparator());
                }
                builder.append("  Repo: ").append(tool.getRepoUrl()).append(System.lineSeparator());
                builder.append("  Summary: ").append(tool.getSummary()).append(System.lineSeparator()).append(System.lineSeparator());
            }

            toolInventoryStatusLabel.setText(response.isAvailable()
                    ? "Kali WSL tool inventory loaded."
                    : "Kali WSL tool inventory is unavailable.");
            toolAvailabilityField.setText("Installed " + response.getInstalledCount() + ", missing " + response.getMissingCount());
            toolAvailabilityField.setCaretPosition(0);
            detectedToolInventoryArea.setText(builder.toString().trim());
            detectedToolInventoryArea.setCaretPosition(0);
        });
    }

    public void showToolInventoryError(String message) {
        SwingUtilities.invokeLater(() -> {
            refreshToolInventoryButton.setEnabled(true);
            String text = message == null || message.isBlank()
                    ? "Unable to load the Kali WSL tool inventory."
                    : message;
            if (text.contains("ClosedChannelException")) {
                text = "The Kali WSL inventory request was interrupted by a transient local HTTP channel reset. Retry once. "
                        + "If it keeps happening, restart the AI Bridge server and refresh the inventory again.";
            }
            toolInventoryStatusLabel.setText(text);
            toolAvailabilityField.setText("Inventory unavailable");
            detectedToolInventoryArea.setText(text);
        });
    }

    private void updateBackendHealthLabel(String text, Color color) {
        SwingUtilities.invokeLater(() -> {
            backendHealthLabel.setText(text);
            backendHealthLabel.setForeground(color);
        });
    }

    public void showCollaboratorSyncLoading() {
        SwingUtilities.invokeLater(() -> {
            collaboratorSyncStatusLabel.setText("Syncing AI Bridge Collaborator interactions...");
            syncCollaboratorButton.setEnabled(false);
            rotateCollaboratorButton.setEnabled(false);
        });
    }

    public void showCollaboratorClientState(String payload, String status) {
        SwingUtilities.invokeLater(() -> {
            collaboratorPayloadField.setText(payload == null || payload.isBlank()
                    ? "No payload is available yet."
                    : payload);
            collaboratorPayloadField.setCaretPosition(0);
            collaboratorSyncStatusLabel.setText(
                    status == null || status.isBlank()
                            ? "AI Bridge Collaborator client is ready."
                            : status
            );
            syncCollaboratorButton.setEnabled(true);
            rotateCollaboratorButton.setEnabled(true);
            copyCollaboratorPayloadButton.setEnabled(payload != null && !payload.isBlank());
        });
    }

    public void showCollaboratorSyncResult(String mergedEvidence, String payload, String status) {
        SwingUtilities.invokeLater(() -> {
            collaboratorEvidenceArea.setText(mergedEvidence == null ? "" : mergedEvidence);
            collaboratorEvidenceArea.setCaretPosition(0);
            showCollaboratorClientState(payload, status);
        });
    }

    public void showCollaboratorSyncError(String message) {
        SwingUtilities.invokeLater(() -> {
            collaboratorSyncStatusLabel.setText(
                    message == null || message.isBlank()
                            ? "Unable to sync the AI Bridge Collaborator client."
                            : "Collaborator sync failed: " + message
            );
            syncCollaboratorButton.setEnabled(true);
            rotateCollaboratorButton.setEnabled(true);
        });
    }

    public void showScanBridgeState(String summary, String status, boolean hasRecentIssues, boolean hasTargetIssues) {
        SwingUtilities.invokeLater(() -> {
            scanBridgeSummaryArea.setText(summary == null || summary.isBlank()
                    ? "No Burp scan issues have been observed by AI Bridge yet."
                    : summary);
            scanBridgeSummaryArea.setCaretPosition(0);
            scanBridgeStatusLabel.setText(
                    status == null || status.isBlank()
                            ? "Burp scan monitoring is active. Scanner findings are available for manual AI Bridge review."
                            : status
            );
            analyzeRecentScanButton.setEnabled(true);
            analyzeCurrentTargetScanButton.setEnabled(true);
            analyzeRecentScanButton.setToolTipText(hasRecentIssues
                    ? "Send the most recent Burp scan findings to AI Bridge."
                    : "No recent Burp scan findings are available yet.");
            analyzeCurrentTargetScanButton.setToolTipText(hasTargetIssues
                    ? "Send Burp findings for the current target to AI Bridge."
                    : "No Burp findings are available yet for the current target.");
        });
    }

    public void setCurrentScanTarget(String targetUrl) {
        SwingUtilities.invokeLater(() -> {
            scanTargetField.setText(targetUrl == null ? "" : targetUrl);
            scanTargetField.setCaretPosition(0);
        });
    }

    public String scanTargetUrl() {
        return scanTargetField.getText().trim();
    }

    public void showScanLaunchStatus(String message) {
        SwingUtilities.invokeLater(() -> {
            scanLaunchStatusArea.setText(
                    message == null || message.isBlank()
                            ? "Scan launch status is unavailable."
                            : message
            );
            scanLaunchStatusArea.setCaretPosition(0);
            launchScanButton.setEnabled(true);
            addScanBcheckButton.setEnabled(true);
        });
    }

    public void showScanLaunchStarting() {
        SwingUtilities.invokeLater(() -> {
            scanLaunchStatusArea.setText("Starting Burp scan task from AI Bridge...");
            scanLaunchStatusArea.setCaretPosition(0);
            launchScanButton.setEnabled(false);
        });
    }

    public void showBurpSettingsSyncStarting(String message) {
        SwingUtilities.invokeLater(() -> {
            operatorInputStatusLabel.setText(
                    message == null || message.isBlank()
                            ? "Applying AI Bridge-managed Burp scope and header settings..."
                            : message
            );
            applyBurpSettingsButton.setEnabled(false);
            disableBurpSettingsButton.setEnabled(false);
        });
    }

    public void showBurpSettingsSyncStatus(String message, boolean syncedRulesActive) {
        SwingUtilities.invokeLater(() -> {
            operatorInputStatusLabel.setText(
                    message == null || message.isBlank()
                            ? "AI Bridge can recommend Burp settings and sync supported scope/header rules."
                            : message
            );
            applyBurpSettingsButton.setEnabled(burpSettingsApplier != null);
            disableBurpSettingsButton.setEnabled(burpSettingsDisabler != null && syncedRulesActive);
        });
    }

    public void showBcheckCatalogLoading() {
        SwingUtilities.invokeLater(() -> {
            addScanBcheckButton.setEnabled(false);
            scanLaunchStatusArea.setText("Loading the upstream BCheck catalog from the AI Bridge backend...");
            scanLaunchStatusArea.setCaretPosition(0);
        });
    }

    public void showBcheckCatalogChooser(List<BCheckCatalogEntry> entries) {
        SwingUtilities.invokeLater(() -> {
            addScanBcheckButton.setEnabled(true);
            if (entries == null || entries.isEmpty()) {
                showScanLaunchStatus("No BChecks were returned by the AI Bridge catalog.");
                return;
            }

            JTextField searchField = new JTextField();
            searchField.putClientProperty("JTextField.placeholderText", "Search by name, path, tag, vuln class, or usage hint");

            JTabbedPane tabs = new JTabbedPane();
            List<String> tabKeys = List.of("recommended", "matching", "all");
            List<String> tabLabels = List.of("AI Recommended", "Matching Classes", "Full Catalog");
            List<JList<BCheckCatalogEntry>> tabLists = List.of(
                    buildCatalogList(),
                    buildCatalogList(),
                    buildCatalogList()
            );

            for (int index = 0; index < tabLabels.size(); index++) {
                tabs.addTab(tabLabels.get(index), new JScrollPane(tabLists.get(index)));
            }

            java.util.function.Consumer<String> applyFilter = filterText -> {
                String filter = filterText == null ? "" : filterText.trim().toLowerCase();
                for (int index = 0; index < tabKeys.size(); index++) {
                    List<BCheckCatalogEntry> filtered = filterCatalogEntries(entries, filter, tabKeys.get(index));
                    populateCatalogList(tabLists.get(index), filtered);
                    tabs.setTitleAt(index, tabLabels.get(index) + " (" + filtered.size() + ")");
                }
                selectPreferredCatalogTab(tabs, tabLists);
            };
            applyFilter.accept("");

            searchField.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent event) {
                    applyFilter.accept(searchField.getText());
                }

                @Override
                public void removeUpdate(DocumentEvent event) {
                    applyFilter.accept(searchField.getText());
                }

                @Override
                public void changedUpdate(DocumentEvent event) {
                    applyFilter.accept(searchField.getText());
                }
            });

            JPanel panel = new JPanel(new BorderLayout(8, 8));
            panel.add(buildTextFieldBlock("Search Catalog", searchField), BorderLayout.NORTH);
            panel.add(tabs, BorderLayout.CENTER);

            int choice = javax.swing.JOptionPane.showConfirmDialog(
                    mainPanel,
                    panel,
                    "Add BChecks From Catalog",
                    javax.swing.JOptionPane.OK_CANCEL_OPTION,
                    javax.swing.JOptionPane.PLAIN_MESSAGE
            );
            if (choice != javax.swing.JOptionPane.OK_OPTION) {
                showScanLaunchStatus("BCheck catalog selection canceled.");
                return;
            }

            JList<BCheckCatalogEntry> activeList = tabLists.get(tabs.getSelectedIndex());
            List<BCheckCatalogEntry> selected = activeList == null ? List.of() : activeList.getSelectedValuesList();
            if (selected.isEmpty()) {
                showScanLaunchStatus("Select at least one BCheck from the catalog.");
                return;
            }

            for (BCheckCatalogEntry entry : selected) {
                addScanBcheckEntry(entry.selectionLabel(), false);
            }
            if (!scanLaunchBcheckModel.isEmpty()) {
                scanLaunchBcheckList.setSelectionInterval(0, scanLaunchBcheckModel.size() - 1);
            }
            showScanLaunchStatus("Added " + selected.size() + " BCheck checklist entr" + (selected.size() == 1 ? "y." : "ies."));
        });
    }

    private void selectPreferredCatalogTab(JTabbedPane tabs, List<JList<BCheckCatalogEntry>> tabLists) {
        int currentIndex = tabs.getSelectedIndex();
        if (currentIndex >= 0 && currentIndex < tabLists.size()) {
            DefaultListModel<BCheckCatalogEntry> currentModel = (DefaultListModel<BCheckCatalogEntry>) tabLists.get(currentIndex).getModel();
            if (!currentModel.isEmpty()) {
                return;
            }
        }

        for (int index = 0; index < tabLists.size(); index++) {
            DefaultListModel<BCheckCatalogEntry> model = (DefaultListModel<BCheckCatalogEntry>) tabLists.get(index).getModel();
            if (!model.isEmpty()) {
                tabs.setSelectedIndex(index);
                return;
            }
        }
        tabs.setSelectedIndex(tabLists.size() - 1);
    }

    private JList<BCheckCatalogEntry> buildCatalogList() {
        DefaultListModel<BCheckCatalogEntry> listModel = new DefaultListModel<>();
        JList<BCheckCatalogEntry> catalogList = new JList<>(listModel);
        catalogList.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        catalogList.setVisibleRowCount(14);
        catalogList.setCellRenderer(new javax.swing.DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(
                    JList<?> list,
                    Object value,
                    int index,
                    boolean isSelected,
                    boolean cellHasFocus
            ) {
                JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof BCheckCatalogEntry entry) {
                    label.setText(entry.displayLabel());
                    label.setToolTipText("<html>" + entry.tooltipText().replace(System.lineSeparator(), "<br>") + "</html>");
                }
                label.setBorder(new EmptyBorder(4, 6, 4, 6));
                return label;
            }
        });
        return catalogList;
    }

    private void populateCatalogList(JList<BCheckCatalogEntry> list, List<BCheckCatalogEntry> entries) {
        DefaultListModel<BCheckCatalogEntry> model = (DefaultListModel<BCheckCatalogEntry>) list.getModel();
        model.clear();
        for (BCheckCatalogEntry entry : entries) {
            model.addElement(entry);
        }
        if (!model.isEmpty()) {
            list.setSelectedIndex(0);
        }
    }

    private List<BCheckCatalogEntry> filterCatalogEntries(List<BCheckCatalogEntry> entries, String filter, String mode) {
        List<BCheckCatalogEntry> filtered = new ArrayList<>();
        for (BCheckCatalogEntry entry : entries) {
            if (!filter.isBlank() && !entry.matchesFilter(filter)) {
                continue;
            }
            boolean include = switch (mode) {
                case "recommended" -> entry.matchesRecommended(latestRecommendedScanBchecks);
                case "matching" -> entry.matchesPotentialFindings(latestPotentialFindings);
                default -> true;
            };
            if (include) {
                filtered.add(entry);
            }
        }
        return filtered;
    }

    public Component uiComponent() {
        return mainPanel;
    }

    public String caption() {
        return "AI Bridge";
    }

    private JComponent buildHeader() {
        JPanel panel = new JPanel(new BorderLayout(12, 6));
        JLabel titleLabel = new JLabel("AI Bridge");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18f));
        JTextArea subtitleArea = buildHelperText(
                "Human-in-the-loop advisory only. AI Bridge prioritizes request editing, confirmation, and evidence correlation over broad rediscovery."
        );
        subtitleArea.setRows(2);

        JPanel titlePanel = new JPanel(new BorderLayout(8, 4));
        titlePanel.add(titleLabel, BorderLayout.NORTH);
        titlePanel.add(subtitleArea, BorderLayout.CENTER);

        JPanel endpointPanel = new JPanel(new BorderLayout(8, 0));
        endpointPanel.add(new JLabel("FastAPI endpoint:"), BorderLayout.WEST);
        endpointField.putClientProperty("JTextField.placeholderText", "http://127.0.0.1:8000/api/analyze");
        endpointPanel.add(endpointField, BorderLayout.CENTER);
        endpointPanel.setVisible(false);

        JButton toggleEndpointButton = new JButton("Show Backend");
        toggleEndpointButton.addActionListener(ignored -> {
            boolean visible = !endpointPanel.isVisible();
            endpointPanel.setVisible(visible);
            toggleEndpointButton.setText(visible ? "Hide Backend" : "Show Backend");
            endpointPanel.revalidate();
        });

        JPanel topRow = new JPanel(new BorderLayout(8, 0));
        topRow.add(titlePanel, BorderLayout.CENTER);
        topRow.add(toggleEndpointButton, BorderLayout.EAST);

        panel.add(topRow, BorderLayout.NORTH);
        panel.add(endpointPanel, BorderLayout.SOUTH);
        return panel;
    }

    private JTabbedPane buildWorkspaceTabs() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        tabs.addTab("Investigations", buildInvestigationsPanel());

        JPanel advisoryPanel = new JPanel(new BorderLayout(12, 12));
        advisoryPanel.add(buildMetadataPanel(), BorderLayout.NORTH);
        advisoryPanel.add(resultsTabs, BorderLayout.CENTER);
        advisoryPanel.add(buildReportExportPanel(), BorderLayout.SOUTH);

        tabs.addTab("Advisory", advisoryPanel);
        tabs.addTab("Suggestion Queue", buildSuggestionQueueTab());
        tabs.addTab("Operator Console", buildQuestionsSection());
        tabs.addTab("AI-Bridge Settings", buildAiBridgeSettingsPanel());
        return tabs;
    }

    private JComponent buildInvestigationsPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));

        JPanel header = new JPanel(new BorderLayout(8, 0));
        JPanel settingsRow = new JPanel(new BorderLayout(8, 0));
        reuseRepeaterInvestigationsCheckBox.setOpaque(false);
        settingsRow.add(reuseRepeaterInvestigationsCheckBox, BorderLayout.WEST);
        settingsRow.add(investigationHintArea, BorderLayout.CENTER);
        header.add(settingsRow, BorderLayout.CENTER);

        investigationTabs.addChangeListener(ignored -> handleInvestigationSelectionChanged());
        investigationTabs.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() != 2 || !SwingUtilities.isLeftMouseButton(event)) {
                    return;
                }
                int index = investigationTabs.indexAtLocation(event.getX(), event.getY());
                if (index >= 0) {
                    promptRenameInvestigation(index);
                }
            }
        });
        reuseRepeaterInvestigationsCheckBox.addActionListener(ignored -> {
            if (repeaterReuseSettingListener != null) {
                repeaterReuseSettingListener.accept(reuseRepeaterInvestigationsCheckBox.isSelected());
            }
        });

        panel.add(header, BorderLayout.NORTH);
        panel.add(investigationTabs, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildMetadataPanel() {
        JPanel metadataPanel = new JPanel(new GridLayout(0, 6, 10, 6));
        metadataPanel.setBorder(BorderFactory.createTitledBorder("Assessment Context"));
        metadataPanel.add(buildLabelValue("Status", statusLabel));
        metadataPanel.add(buildLabelValue("Backend", backendHealthLabel));
        metadataPanel.add(buildLabelValue("Method", methodLabel));
        metadataPanel.add(buildLabelValue("Updated", updatedLabel));
        metadataPanel.add(buildLabelValue("Target", targetLabel));
        metadataPanel.add(buildLabelValue("Runtime", activeProfileField));
        metadataPanel.add(buildLabelValue("Provider Route", providerRouteField));
        metadataPanel.add(buildLabelValue("Time Budget", timeBudgetCombo));
        metadataPanel.add(buildLabelValue("ETA", estimatedDurationField));
        metadataPanel.add(buildLabelValue("Complexity", complexityField));
        metadataPanel.add(buildLabelValue("Review Scope", scanScopeSummaryField));
        metadataPanel.add(buildLabelValue("Nuclei Tags", nucleiTagsField));
        metadataPanel.add(buildLabelValue("SecLists Path", seclistsPathField));
        metadataPanel.add(buildLabelValue("Primary Action", primaryNextActionField));
        metadataPanel.add(buildLabelValue("Tool Availability", toolAvailabilityField));
        metadataPanel.add(buildLabelValue("Project Readiness", projectReadinessField));
        metadataPanel.add(buildLabelValue("Finding Chips", findingChipsPanel));
        metadataPanel.add(buildLabelValue("Confidence Chips", confidenceChipsPanel));
        return metadataPanel;
    }

    private JPanel buildReportExportPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 8, 0));
        panel.setBorder(BorderFactory.createTitledBorder("Report Export"));
        panel.add(buildLabelValue("Report JSON", reportJsonField));
        panel.add(buildLabelValue("Report Markdown", reportMarkdownField));
        return panel;
    }

    private JTabbedPane buildResultsTabs() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        tabs.addTab(RESULTS_TAB_REQUEST_PLAN, buildRequestPlanPanel());
        tabs.addTab(RESULTS_TAB_AI_ANALYSIS, wrapScroll(RESULTS_TAB_AI_ANALYSIS, analysisArea, 14));
        tabs.addTab(RESULTS_TAB_FINDINGS, buildFindingsTab());
        tabs.addTab(RESULTS_TAB_REASONING, buildReasoningTab());
        tabs.addTab(RESULTS_TAB_TOOLING, buildToolingTab());
        tabs.addTab(RESULTS_TAB_WORKFLOW, buildWorkflowTab());
        return tabs;
    }

    private JComponent buildFindingsTab() {
        return buildResultsStackTab(
                sectionPanel("Potential Vulnerabilities", vulnerabilitiesArea, 10),
                sectionPanel("Confidence By Class", confidenceArea, 8),
                sectionPanel("Confirmation Playbooks", confirmationPlaybooksArea, 8),
                sectionPanel("History Correlation", historyCorrelationArea, 8),
                sectionPanel("Source Links", sourceLinksArea, 6)
        );
    }

    private JComponent buildToolingTab() {
        return buildResultsStackTab(
                sectionPanel("Kali Tools", kaliToolsArea, 8),
                sectionPanel("Kali Commands", kaliCommandsArea, 8),
                sectionPanel("Payload Lists", payloadListsArea, 8)
        );
    }

    private JComponent buildReasoningTab() {
        return buildResultsStackTab(
                sectionPanel("Reasoning Summary", reasoningSummaryArea, 12),
                sectionPanel("Phase History", phaseHistoryArea, 12)
        );
    }

    private JComponent buildWorkflowTab() {
        return buildResultsStackTab(
                sectionPanel("Project Readiness Checks", projectReadinessArea, 8),
                sectionPanel("Burp Action Checklist", burpActionChecklistArea, 8),
                sectionPanel("Impact Paths", impactPathsArea, 8)
        );
    }

    private JComponent buildResultsStackTab(JComponent... sections) {
        ScrollableStackPanel content = new ScrollableStackPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        for (int index = 0; index < sections.length; index++) {
            content.add(sections[index]);
            if (index + 1 < sections.length) {
                content.add(Box.createVerticalStrut(8));
            }
        }

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        return scrollPane;
    }

    private JPanel sectionPanel(String title, JTextArea textArea, int rows) {
        textArea.setRows(rows);
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(textArea, BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildRequestPlanPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder());
        JScrollPane planScroll = wrapScroll("Request Plan", requestPlanArea, 16);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actions.add(copyRequestPlanButton);
        actions.add(copyPayloadsButton);
        actions.add(copyCommandsButton);
        actions.add(copyFullAdvisoryButton);
        panel.add(planScroll, BorderLayout.CENTER);
        panel.add(actions, BorderLayout.SOUTH);
        return panel;
    }

    private JComponent buildSuggestionQueueTab() {
        JPanel followUpPanel = buildSuggestionFollowUpPanel();
        JPanel lowerPanel = new JPanel(new BorderLayout(8, 8));
        lowerPanel.add(followUpPanel, BorderLayout.CENTER);
        lowerPanel.add(buildFeedbackPanel(), BorderLayout.SOUTH);
        JScrollPane queueScrollPane = wrapScroll("Suggestion Queue", suggestionQueueArea, 16);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, queueScrollPane, lowerPanel);
        splitPane.setResizeWeight(0.72d);
        splitPane.setDividerSize(8);
        splitPane.setContinuousLayout(true);
        splitPane.setOneTouchExpandable(true);
        splitPane.setBorder(BorderFactory.createEmptyBorder());
        return splitPane;
    }

    private JPanel buildSuggestionFollowUpPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Ask AI For The Next Exact Step"));
        configureTextArea(suggestionFollowUpArea, 120);
        suggestionFollowUpArea.setRows(7);

        JTextArea helperLabel = buildHelperText(
                "Name the queue step, parameter, insertion point, or payload family you want expanded. Ask for the exact request change, what to compare, or the confirmation step to try next."
        );
        panel.add(helperLabel, BorderLayout.NORTH);
        panel.add(new JScrollPane(suggestionFollowUpArea), BorderLayout.CENTER);

        JPanel footer = new JPanel(new BorderLayout(8, 4));
        suggestionFollowUpStatusLabel.setForeground(HELPER_COLOR);
        footer.add(suggestionFollowUpStatusLabel, BorderLayout.NORTH);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton useQueueButton = new JButton("Use Queue Text");
        useQueueButton.addActionListener(ignored -> appendSelectedSuggestionToFollowUp());
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(ignored -> suggestionFollowUpArea.setText(""));
        cancelSuggestionButton.addActionListener(ignored -> cancelFollowUp());
        actions.add(useQueueButton);
        actions.add(clearButton);
        actions.add(cancelSuggestionButton);
        actions.add(askSuggestionButton);
        footer.add(actions, BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);
        return panel;
    }

    private JScrollPane wrapScroll(String title, JTextArea textArea, int rows) {
        textArea.setRows(rows);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder(title));
        scrollPane.setMinimumSize(new Dimension(200, 140));
        return scrollPane;
    }

    private JPanel buildQuestionsSection() {
        JPanel section = new JPanel(new BorderLayout(8, 8));
        section.setBorder(BorderFactory.createTitledBorder("Evidence, Constraints, and Clarifications"));

        JTextArea helperLabel = buildHelperText(
                "Use this workspace to add operator constraints, saved project context, BApp findings, Collaborator notes, shared tool output, and answers to AI Bridge follow-up questions."
        );
        section.add(helperLabel, BorderLayout.NORTH);
        section.add(buildOperatorInputPanel(), BorderLayout.CENTER);

        JScrollPane questionScrollPane = new JScrollPane(questionsPanel);
        questionScrollPane.setPreferredSize(new Dimension(0, QUESTIONS_HEIGHT));
        questionScrollPane.setMinimumSize(new Dimension(0, 160));

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton clearButton = new JButton("Clear Answers");
        clearButton.addActionListener(ignored -> clearAnswers());
        JButton copyButton = new JButton("Copy Answers as JSON");
        copyButton.addActionListener(ignored -> copyAnswersToClipboard());
        buttonRow.add(clearButton);
        buttonRow.add(copyButton);

        questionSectionPanel.removeAll();
        questionSectionPanel.add(questionScrollPane, BorderLayout.CENTER);
        questionSectionPanel.add(buttonRow, BorderLayout.SOUTH);
        questionSectionPanel.setBorder(BorderFactory.createTitledBorder("AI Follow-Up Questions"));
        section.add(questionSectionPanel, BorderLayout.SOUTH);
        renderQuestionInputs(List.of());
        return section;
    }

    private JPanel buildOperatorInputPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));

        JTabbedPane interactionTabs = new JTabbedPane();
        interactionTabs.addTab("Tool Help", buildToolHelpPanel());
        interactionTabs.addTab("Program Context", buildProgramContextPanel());
        interactionTabs.addTab("BApp Findings", buildBappFindingsPanel());
        interactionTabs.addTab("HTTP Logger", buildLoggerEvidencePanel());
        interactionTabs.addTab("Collaborator", buildCollaboratorPanel());
        interactionTabs.addTab("Shared Results", buildSharedResultsPanel());

        JPanel actionRow = new JPanel(new BorderLayout(8, 0));
        operatorInputStatusLabel.setForeground(HELPER_COLOR);
        actionRow.add(operatorInputStatusLabel, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        cancelFollowUpButton.addActionListener(ignored -> cancelFollowUp());
        buttons.add(cancelFollowUpButton);
        buttons.add(submitAnswersButton);
        actionRow.add(buttons, BorderLayout.EAST);

        panel.add(interactionTabs, BorderLayout.CENTER);
        panel.add(actionRow, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildToolHelpPanel() {
        JPanel toolHelpPanel = new JPanel(new BorderLayout(8, 8));
        toolHelpPanel.setBorder(BorderFactory.createTitledBorder("Optional Tool Help"));
        configureTextArea(toolHelpArea, 110);
        detectedToolInventoryArea.setRows(10);

        JPanel detectedPanel = new JPanel(new BorderLayout(8, 8));
        detectedPanel.setBorder(BorderFactory.createTitledBorder("Detected Kali WSL Tool Inventory"));
        JPanel detectedHeader = new JPanel(new BorderLayout(8, 0));
        toolInventoryStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        detectedHeader.add(toolInventoryStatusLabel, BorderLayout.CENTER);
        detectedHeader.add(refreshToolInventoryButton, BorderLayout.EAST);
        detectedPanel.add(detectedHeader, BorderLayout.NORTH);
        detectedPanel.add(new JScrollPane(detectedToolInventoryArea), BorderLayout.CENTER);

        JPanel manualPanel = new JPanel(new BorderLayout(8, 8));
        manualPanel.setBorder(BorderFactory.createTitledBorder("Additional Manual Help Or Overrides"));
        manualPanel.add(buildHelperText("Paste extra help text only if you want to override or supplement the detected Kali inventory."), BorderLayout.NORTH);
        manualPanel.add(new JScrollPane(toolHelpArea), BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, detectedPanel, manualPanel);
        splitPane.setResizeWeight(0.58d);
        splitPane.setDividerSize(8);
        splitPane.setContinuousLayout(true);
        splitPane.setOneTouchExpandable(true);
        toolHelpPanel.add(splitPane, BorderLayout.CENTER);
        return toolHelpPanel;
    }

    private JPanel buildProgramContextPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Bug Bounty Program Context"));

        configureTextArea(scopeIncludesArea, 70);
        configureTextArea(scopeExcludesArea, 70);
        configureTextArea(customHeadersArea, 70);
        configureTextArea(programPolicyArea, 90);
        configureTextArea(responseDeltaArea, 80);

        rateLimitField.putClientProperty("JTextField.placeholderText", "Example: 5 req/s max");
        maxConcurrencyField.putClientProperty("JTextField.placeholderText", "Example: 1 or 2");

        ScrollableStackPanel content = new ScrollableStackPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        JPanel helperRow = new JPanel(new BorderLayout(8, 0));
        JTextArea helper = buildHelperText("Paste policy text once, then let AI Bridge extract concurrency, headers, scope hints, and timing notes.");
        helperRow.add(helper, BorderLayout.CENTER);
        JPanel helperButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        helperButtons.add(parseProgramRulesButton);
        helperButtons.add(applyBurpSettingsButton);
        helperButtons.add(disableBurpSettingsButton);
        helperRow.add(helperButtons, BorderLayout.EAST);
        content.add(helperRow);
        content.add(Box.createVerticalStrut(10));

        JTextArea burpSyncNote = buildHelperText(
                "Direct Burp sync is limited to project scope and in-scope custom headers. Other Burp settings remain recommendation-only."
        );
        content.add(burpSyncNote);
        content.add(Box.createVerticalStrut(10));
        content.add(buildAreaField("In-Scope URLs", scopeIncludesArea, "One per line or a short summary of in-scope targets."));
        content.add(Box.createVerticalStrut(10));
        content.add(buildAreaField("Out-of-Scope URLs", scopeExcludesArea, "One per line or a short summary of excluded targets."));
        content.add(Box.createVerticalStrut(10));
        content.add(buildInlineFields());
        content.add(Box.createVerticalStrut(10));
        content.add(buildAreaField("Custom Headers", customHeadersArea, "One header per line, for example: X-Bug-Bounty: researcher@example.com"));
        content.add(Box.createVerticalStrut(10));
        responseDeltaArea.setRows(3);
        content.add(buildAreaField("Observed Response Delta", responseDeltaArea, "Paste the latest approved comparison result, for example: status 302 -> 200, length +840, redirect removed."));
        content.add(Box.createVerticalStrut(10));
        content.add(buildAreaField("Program Notes", programPolicyArea, "Paste safe-testing notes such as allowed methods, hours, or scan restrictions."));

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildReviewScopePanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Skip Vulnerability Classes For This Request"));
        skippedScopeList.setVisibleRowCount(10);

        JPanel top = new JPanel(new BorderLayout(8, 8));
        top.add(buildHelperText("Skip any vulnerability classes you do not want considered for this request. Model routing and runtime strategy are handled by AI Bridge automatically."), BorderLayout.NORTH);
        JPanel skipRow = new JPanel(new BorderLayout(8, 0));
        skipRow.add(new JLabel("Skip class"), BorderLayout.WEST);
        skipRow.add(skipClassCombo, BorderLayout.CENTER);
        JPanel skipButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        skipButtons.add(addSkipClassButton);
        skipButtons.add(removeSkipClassButton);
        skipButtons.add(resetSkipClassesButton);
        skipRow.add(skipButtons, BorderLayout.EAST);

        JPanel controls = new JPanel(new BorderLayout(8, 8));
        controls.add(skipRow, BorderLayout.CENTER);
        top.add(controls, BorderLayout.SOUTH);

        panel.add(top, BorderLayout.NORTH);
        panel.add(new JScrollPane(skippedScopeList), BorderLayout.CENTER);
        panel.add(buildHelperText("Anything in this skip list is suppressed for the current request. Everything else remains in scope."), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildSharedResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Shared Results, Files, and Timeline"));
        configureTextArea(toolResultsArea, 150);

        JPanel entryPanel = new JPanel(new BorderLayout(8, 8));
        entryPanel.add(buildHelperText("Paste tool output, notes, or local result paths here. You can also attach result files or folders and AI Bridge will keep the visible path list with this request."), BorderLayout.NORTH);
        entryPanel.add(new JScrollPane(toolResultsArea), BorderLayout.CENTER);

        JPanel entryControls = new JPanel(new BorderLayout(8, 0));
        evidenceSourceField.putClientProperty("JTextField.placeholderText", "Source label, for example: nuclei, curl, ffuf, notes, file path");
        entryControls.add(evidenceSourceField, BorderLayout.CENTER);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton addFilesButton = new JButton("Attach Files");
        addFilesButton.addActionListener(ignored -> chooseAndAppendPaths(toolResultsArea, "Attach result files or folders", JFileChooser.FILES_AND_DIRECTORIES));
        buttons.add(addFilesButton);
        buttons.add(addEvidenceButton);
        buttons.add(clearEvidenceButton);
        entryControls.add(buttons, BorderLayout.EAST);
        entryPanel.add(entryControls, BorderLayout.SOUTH);

        JPanel timelinePanel = new JPanel(new BorderLayout(8, 8));
        timelinePanel.setBorder(BorderFactory.createTitledBorder("Evidence Timeline"));
        evidenceTimelineArea.setRows(10);
        timelinePanel.add(new JScrollPane(evidenceTimelineArea), BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, entryPanel, timelinePanel);
        splitPane.setResizeWeight(0.48d);
        splitPane.setDividerSize(8);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(BorderFactory.createEmptyBorder());
        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildAiBridgeSettingsPanel() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBorder(BorderFactory.createEmptyBorder());
        configureTextArea(burpConfigExportArea, 120);
        configureTextArea(burpScreenshotAuditArea, 110);
        configureTextArea(savedLoadedBurpToolsArea, 90);
        configureTextArea(savedProgramPolicyArea, 100);
        configureTextArea(savedProgramScreenshotArea, 100);

        JTextArea introArea = buildReadOnlyTextArea(
                "Use this tab as the saved memory for the current Burp project. Keep the installed Burp tools, baseline settings, program rules, and screenshots here so AI Bridge can reuse them across investigations."
        );
        introArea.setRows(3);
        JPanel introPanel = new JPanel(new BorderLayout(8, 8));
        introPanel.setBorder(BorderFactory.createTitledBorder("How This Works"));
        introPanel.add(introArea, BorderLayout.CENTER);

        JPanel summaryPanel = new JPanel(new GridBagLayout());
        summaryPanel.setBorder(BorderFactory.createTitledBorder("Project Profile"));
        GridBagConstraints summaryConstraints = new GridBagConstraints();
        summaryConstraints.gridx = 0;
        summaryConstraints.gridy = 0;
        summaryConstraints.weightx = 1.0d;
        summaryConstraints.fill = GridBagConstraints.HORIZONTAL;
        summaryConstraints.anchor = GridBagConstraints.NORTHWEST;
        summaryConstraints.insets = new Insets(0, 0, 10, 0);
        summaryPanel.add(buildLabelValue("Current Burp Project", aiBridgeSettingsProjectField), summaryConstraints);
        summaryConstraints.gridy++;
        summaryPanel.add(buildLabelValue("Last Screenshot Review", aiBridgeVisionStatusField), summaryConstraints);
        summaryConstraints.gridy++;
        summaryPanel.add(buildLabelValue("Auto Apply Saved Context", autoUseSavedSettingsCheckBox), summaryConstraints);
        summaryConstraints.gridy++;
        JTextField persistenceField = buildReadOnlyField("Saved in Burp extension data for this Burp project and restored after restart.");
        summaryPanel.add(buildLabelValue("Persistence", persistenceField), summaryConstraints);
        summaryConstraints.gridy++;
        aiBridgeSettingsStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        summaryPanel.add(aiBridgeSettingsStatusLabel, summaryConstraints);
        summaryConstraints.gridy++;
        summaryConstraints.insets = new Insets(4, 0, 0, 0);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actions.add(reloadSettingsButton);
        actions.add(clearSettingsButton);
        actions.add(saveSettingsButton);
        summaryPanel.add(actions, summaryConstraints);

        JPanel header = new JPanel(new BorderLayout(12, 12));
        header.add(introPanel, BorderLayout.NORTH);
        header.add(summaryPanel, BorderLayout.CENTER);

        JPanel guidancePanel = new JPanel(new BorderLayout(8, 8));
        guidancePanel.setBorder(BorderFactory.createTitledBorder("Latest AI Burp Settings Guidance"));
        burpSettingsArea.setRows(8);
        guidancePanel.add(buildHelperText("AI Bridge updates this after each advisory so the current Burp-wide settings guidance stays in one place."), BorderLayout.NORTH);
        guidancePanel.add(burpSettingsArea, BorderLayout.CENTER);

        JPanel burpConfigPanel = new JPanel(new BorderLayout(8, 8));
        burpConfigPanel.setBorder(BorderFactory.createTitledBorder("Burp Global Baseline"));
        burpConfigPanel.add(buildHelperText("Save the Burp-wide baseline here. AI Bridge uses it to recommend which global settings to keep, adjust, or review before scanning."), BorderLayout.NORTH);

        JPanel loadedToolsPanel = new JPanel(new BorderLayout(8, 8));
        loadedToolsPanel.setBorder(BorderFactory.createTitledBorder("Loaded Burp Tools / BApps"));
        loadedToolsPanel.add(buildHelperText("List the Burp tools and BApps already installed for this project, one per line. Example: Logger++, Burp Logger, Param Miner, Autorize/AuthMatrix, JWT Editor."), BorderLayout.NORTH);
        loadedToolsPanel.add(savedLoadedBurpToolsArea, BorderLayout.CENTER);

        JPanel configPanel = new JPanel(new BorderLayout(8, 8));
        configPanel.setBorder(BorderFactory.createTitledBorder("Burp Config Export"));
        configPanel.add(burpConfigExportArea, BorderLayout.CENTER);

        JPanel screenshotPanel = new JPanel(new BorderLayout(8, 8));
        screenshotPanel.setBorder(BorderFactory.createTitledBorder("Burp Settings Screenshot Paths / Notes"));
        JPanel screenshotHeader = new JPanel(new BorderLayout(8, 8));
        screenshotHeader.add(buildHelperText("Paste one local image path or file:/// URI per line, plus any notes about the Burp settings screenshot."), BorderLayout.CENTER);
        JButton attachBurpScreenshotsButton = new JButton("Attach Screenshots");
        attachBurpScreenshotsButton.addActionListener(ignored -> chooseAndAppendPaths(
                burpScreenshotAuditArea,
                "Attach Burp settings screenshots",
                JFileChooser.FILES_ONLY
        ));
        screenshotHeader.add(attachBurpScreenshotsButton, BorderLayout.EAST);
        screenshotPanel.add(screenshotHeader, BorderLayout.NORTH);
        screenshotPanel.add(burpScreenshotAuditArea, BorderLayout.CENTER);

        ScrollableStackPanel burpStack = new ScrollableStackPanel();
        burpStack.setLayout(new BoxLayout(burpStack, BoxLayout.Y_AXIS));
        burpStack.add(loadedToolsPanel);
        burpStack.add(Box.createVerticalStrut(8));
        burpStack.add(configPanel);
        burpStack.add(Box.createVerticalStrut(8));
        burpStack.add(screenshotPanel);

        burpConfigPanel.add(burpStack, BorderLayout.CENTER);

        JPanel programPanel = new JPanel(new BorderLayout(8, 8));
        programPanel.setBorder(BorderFactory.createTitledBorder("Bug Bounty Program Context"));
        programPanel.add(buildHelperText("Save the program rules and website screenshots here. AI Bridge uses them to recommend concurrency, headers, allowed HTTP versions, scope rules, and other pre-scan decisions."), BorderLayout.NORTH);

        JPanel programNotesPanel = new JPanel(new BorderLayout(8, 8));
        programNotesPanel.setBorder(BorderFactory.createTitledBorder("Program Rules / Notes"));
        programNotesPanel.add(savedProgramPolicyArea, BorderLayout.CENTER);

        JPanel programScreenshotPanel = new JPanel(new BorderLayout(8, 8));
        programScreenshotPanel.setBorder(BorderFactory.createTitledBorder("Program Screenshot Paths / Notes"));
        JPanel programScreenshotHeader = new JPanel(new BorderLayout(8, 8));
        programScreenshotHeader.add(buildHelperText("Paste website screenshot file paths or notes that mention concurrency, credentials, allowed HTTP versions, excluded IPs, timing, or scope rules."), BorderLayout.CENTER);
        JButton attachProgramScreenshotsButton = new JButton("Attach Screenshots");
        attachProgramScreenshotsButton.addActionListener(ignored -> chooseAndAppendPaths(
                savedProgramScreenshotArea,
                "Attach program screenshots",
                JFileChooser.FILES_ONLY
        ));
        programScreenshotHeader.add(attachProgramScreenshotsButton, BorderLayout.EAST);
        programScreenshotPanel.add(programScreenshotHeader, BorderLayout.NORTH);
        programScreenshotPanel.add(savedProgramScreenshotArea, BorderLayout.CENTER);

        ScrollableStackPanel programStack = new ScrollableStackPanel();
        programStack.setLayout(new BoxLayout(programStack, BoxLayout.Y_AXIS));
        programStack.add(programNotesPanel);
        programStack.add(Box.createVerticalStrut(8));
        programStack.add(programScreenshotPanel);
        programPanel.add(programStack, BorderLayout.CENTER);

        ScrollableStackPanel content = new ScrollableStackPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(header);
        content.add(Box.createVerticalStrut(10));
        content.add(guidancePanel);
        content.add(Box.createVerticalStrut(10));
        content.add(burpConfigPanel);
        content.add(Box.createVerticalStrut(10));
        content.add(programPanel);

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.getHorizontalScrollBar().setUnitIncrement(16);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildBappFindingsPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Burp BApp Findings"));
        configureTextArea(bappFindingsArea, 180);
        panel.add(buildHelperText("Paste or keep the relevant findings from Burp extensions here so AI Bridge can correlate them with the active request and Burp-marked issue."), BorderLayout.NORTH);
        panel.add(new JScrollPane(bappFindingsArea), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildLoggerEvidencePanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("HTTP Logger / Logger++ Evidence"));
        configureTextArea(loggerEvidenceArea, 180);
        panel.add(buildHelperText("Paste Burp Logger or Logger++ observations here: filters, comments, status deltas, header diffs, response-length changes, or baseline markers."), BorderLayout.NORTH);
        panel.add(new JScrollPane(loggerEvidenceArea), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildCollaboratorPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Collaborator Evidence"));
        configureTextArea(collaboratorEvidenceArea, 180);
        JPanel header = new JPanel(new BorderLayout(8, 8));
        header.add(buildHelperText("Paste legitimate, in-scope Collaborator observations here, or sync the AI Bridge client to attach unlinked interactions."), BorderLayout.NORTH);

        JPanel payloadPanel = new JPanel(new BorderLayout(8, 4));
        payloadPanel.add(new JLabel("AI Bridge Collaborator payload"), BorderLayout.NORTH);
        payloadPanel.add(collaboratorPayloadField, BorderLayout.CENTER);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actions.add(copyCollaboratorPayloadButton);
        actions.add(rotateCollaboratorButton);
        actions.add(syncCollaboratorButton);
        payloadPanel.add(actions, BorderLayout.EAST);

        collaboratorSyncStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        header.add(payloadPanel, BorderLayout.CENTER);
        header.add(collaboratorSyncStatusLabel, BorderLayout.SOUTH);

        panel.add(header, BorderLayout.NORTH);
        panel.add(new JScrollPane(collaboratorEvidenceArea), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildScanBridgePanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createTitledBorder("AI Bridge Scan Workflow"));

        JPanel header = new JPanel(new BorderLayout(8, 6));
        JLabel helper = new JLabel(
                "AI Bridge watches Burp findings, turns them into confirmation guidance, and helps you prepare the next scan or manual check."
        );
        helper.setForeground(UIManager.getColor("Label.disabledForeground"));
        scanBridgeStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        header.add(helper, BorderLayout.NORTH);
        header.add(scanBridgeStatusLabel, BorderLayout.SOUTH);

        configureTextArea(scanBridgeSummaryArea, 220);
        scanBridgeSummaryArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ScrollableStackPanel content = new ScrollableStackPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(buildScanLaunchPanel());
        content.add(Box.createVerticalStrut(10));
        content.add(buildScanBridgeDetailsPanel());

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.getHorizontalScrollBar().setUnitIncrement(16);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        panel.add(header, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildScanLaunchPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("Scan Launch Controls"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        scanTargetField.putClientProperty("JTextField.placeholderText", "https://target.example/path");
        configureTextArea(scanBridgeGuidanceArea, 170);
        scanBridgeGuidanceArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        configureTextArea(newScanHandoffArea, 170);
        newScanHandoffArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        configureTextArea(scanBridgeSummaryArea, 120);
        scanBridgeSummaryArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        configureTextArea(scanLaunchStatusArea, 72);
        scanLaunchStatusArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        scanLaunchStatusArea.setBackground(new Color(0xF8FAFC));
        scanLaunchStatusArea.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0xD0D5DD)),
                new EmptyBorder(6, 6, 6, 6)
        ));
        scanLaunchBcheckList.setVisibleRowCount(6);
        scanLaunchBcheckList.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        scanLaunchBcheckList.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        styleScanBridgeButton(useCurrentTargetButton, 170);
        styleScanBridgeButton(launchScanButton, 150);
        styleScanBridgeButton(addScanBcheckButton, 140);
        styleScanBridgeButton(removeScanBcheckButton, 170);
        styleScanBridgeButton(clearScanBcheckButton, 110);
        styleScanBridgeButton(analyzeCurrentTargetScanButton, 230);
        styleScanBridgeButton(analyzeRecentScanButton, 220);
        panel.add(buildScanLaunchSettingsPanel());
        panel.add(Box.createVerticalStrut(8));
        panel.add(buildScanLaunchBcheckPanel());
        panel.add(Box.createVerticalStrut(8));
        panel.add(buildScanLaunchStatusPanel());
        panel.add(Box.createVerticalStrut(8));
        panel.add(buildScanBridgeActionBar());
        return panel;
    }

    private JPanel buildScanLaunchSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Step 1 - Pick Target And Scan Mode"));

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weightx = 1.0d;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.NORTHWEST;
        constraints.insets = new Insets(0, 0, 8, 0);

        panel.add(buildTextFieldBlock("Target URL", scanTargetField), constraints);
        constraints.gridy++;

        JPanel row = new JPanel(new GridLayout(1, 2, 8, 0));
        row.add(buildComboFieldBlock("Scan type", scanTypeCombo));
        row.add(buildComboFieldBlock("Audit configuration", auditConfigurationCombo));
        panel.add(row, constraints);
        constraints.gridy++;

        JLabel helper = new JLabel(
                "AI Bridge will keep the advanced Burp workflow in the background. Here you only pick the target and the scan mode."
        );
        helper.setForeground(UIManager.getColor("Label.disabledForeground"));
        panel.add(helper, constraints);
        constraints.gridy++;

        constraints.weighty = 1.0d;
        panel.add(Box.createVerticalGlue(), constraints);
        return panel;
    }

    private JPanel buildScanLaunchBcheckPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Step 2 - Review BChecks"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel helper = new JLabel(
                "AI recommendations are preselected when available. Add more from the shared BCheck catalog only if you want extra coverage."
        );
        helper.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actions.add(addScanBcheckButton);
        actions.add(removeScanBcheckButton);
        actions.add(clearScanBcheckButton);

        panel.add(helper, BorderLayout.NORTH);
        panel.add(new JScrollPane(scanLaunchBcheckList), BorderLayout.CENTER);
        panel.add(actions, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildScanLaunchStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Step 3 - Launch Status"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(scanLaunchStatusArea, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildScanBridgeDetailsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(buildScanTextSection(
                "What To Do Next",
                scanBridgeGuidanceArea,
                "This is the short operator view. AI Bridge keeps the longer workflow detail in the background."
        ));
        panel.add(Box.createVerticalStrut(8));
        panel.add(buildScanTextSection(
                "Simple Workflow",
                newScanHandoffArea,
                "Use Copy Burp Workflow if you want the full detailed handoff for note-taking or reporting."
        ));
        panel.add(Box.createVerticalStrut(8));
        panel.add(buildScanTextSection(
                "Observed Scan Findings",
                scanBridgeSummaryArea,
                "Scanner findings seen by AI Bridge for the current target."
        ));
        return panel;
    }

    private JPanel buildScanBridgeActionBar() {
        JPanel panel = new JPanel(new GridLayout(3, 2, 8, 8));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(useCurrentTargetButton);
        panel.add(launchScanButton);
        panel.add(analyzeCurrentTargetScanButton);
        panel.add(analyzeRecentScanButton);
        panel.add(copyNewScanHandoffButton);
        panel.add(new JLabel(""));
        panel.setBorder(new EmptyBorder(2, 0, 0, 0));
        return panel;
    }

    private JPanel buildInlineFields() {
        JPanel row = new JPanel(new GridLayout(1, 2, 8, 0));
        row.add(buildTextFieldBlock("Rate Limit", rateLimitField));
        row.add(buildTextFieldBlock("Max Concurrency", maxConcurrencyField));
        return row;
    }

    private JPanel buildTextFieldBlock(String labelText, JTextField field) {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(new JLabel(labelText), BorderLayout.NORTH);
        panel.add(field, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildComboFieldBlock(String labelText, JComboBox<String> comboBox) {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(new JLabel(labelText), BorderLayout.NORTH);
        panel.add(comboBox, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildAreaField(String title, JTextArea area, String helperText) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0xD0D5DD)),
                new EmptyBorder(8, 8, 8, 8)
        ));
        panel.add(new JLabel(title), BorderLayout.NORTH);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        JTextArea helper = buildHelperText(helperText);
        panel.add(helper, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildStaticTextSection(String title, JTextArea area, String helperText) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(BorderFactory.createTitledBorder(title));
        if (helperText != null && !helperText.isBlank()) {
            JTextArea helper = buildHelperText(helperText);
            panel.add(helper, BorderLayout.NORTH);
        }
        panel.add(area, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildScanTextSection(String title, JTextArea area, String helperText) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(BorderFactory.createTitledBorder(title));
        if (helperText != null && !helperText.isBlank()) {
            JTextArea helper = buildHelperText(helperText);
            panel.add(helper, BorderLayout.NORTH);
        }
        panel.add(area, BorderLayout.CENTER);
        return panel;
    }

    private void configureTextArea(JTextArea area, int preferredHeight) {
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(FORM_FONT);
        area.setMargin(new Insets(6, 6, 6, 6));
        area.setRows(4);
        area.setMinimumSize(new Dimension(200, 60));
        area.setPreferredSize(new Dimension(0, preferredHeight));
        area.setBackground(Color.WHITE);
    }

    private JTextArea buildHelperText(String text) {
        JTextArea area = new JTextArea(text == null ? "" : text);
        area.setEditable(false);
        area.setFocusable(false);
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(HELPER_FONT);
        area.setForeground(HELPER_COLOR);
        area.setBorder(new EmptyBorder(0, 0, 0, 0));
        area.setMargin(new Insets(0, 0, 0, 0));
        return area;
    }

    private void chooseAndAppendPaths(JTextArea targetArea, String dialogTitle, int selectionMode) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(dialogTitle);
        chooser.setFileSelectionMode(selectionMode);
        chooser.setMultiSelectionEnabled(true);
        int result = chooser.showOpenDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        List<String> values = new ArrayList<>();
        File[] selectedFiles = chooser.getSelectedFiles();
        if (selectedFiles != null && selectedFiles.length > 0) {
            for (File file : selectedFiles) {
                if (file != null) {
                    values.add(file.getAbsolutePath());
                }
            }
        } else if (chooser.getSelectedFile() != null) {
            values.add(chooser.getSelectedFile().getAbsolutePath());
        }
        appendUniqueLines(targetArea, values);
    }

    private void appendUniqueLines(JTextArea targetArea, List<String> lines) {
        if (targetArea == null || lines == null || lines.isEmpty()) {
            return;
        }
        List<String> merged = new ArrayList<>();
        String current = safeText(targetArea.getText());
        if (!current.isBlank()) {
            for (String line : current.split("\\R")) {
                String trimmed = line.trim();
                if (!trimmed.isBlank() && !merged.contains(trimmed)) {
                    merged.add(trimmed);
                }
            }
        }
        for (String line : lines) {
            String trimmed = safeText(line).trim();
            if (!trimmed.isBlank() && !merged.contains(trimmed)) {
                merged.add(trimmed);
            }
        }
        targetArea.setText(String.join(System.lineSeparator(), merged));
        markOperatorInputCaptured();
    }

    private void styleScanBridgeButton(JButton button, int preferredWidth) {
        button.setFont(button.getFont().deriveFont(Font.BOLD, 12f));
        button.setPreferredSize(new Dimension(preferredWidth, 34));
    }

    private final class InvestigationWorkspace {
        private final String sessionId;
        private String title;
        private final JPanel root;
        private final JTextArea requestArea;
        private final JTextArea responseArea;
        private final JTextArea contextArea;
        private final JTextArea exactChangeArea;
        private final JTextArea notebookArea;
        private final JTextArea chatTranscriptArea;
        private final JTextArea chatInputArea;
        private final JLabel statusLabel;
        private final JButton submitButton;
        private final List<InvestigationTranscriptEntry> transcriptEntries;
        private final List<InvestigationNotebookEntry> notebookEntries;
        private String baselineRequest;
        private boolean followUpRunning;
        private boolean userRenamed;
        private AssessmentRequest request;
        private AdvisoryResponse response;

        private InvestigationWorkspace(String sessionId, String title) {
            this.sessionId = sessionId;
            this.title = title;
            this.root = new JPanel(new BorderLayout(8, 8));
            this.requestArea = new JTextArea();
            this.responseArea = buildReadOnlyTextArea("");
            this.contextArea = buildReadOnlyTextArea("");
            this.exactChangeArea = buildReadOnlyTextArea("AI Bridge will summarize the exact request changes for this investigation here.");
            this.notebookArea = buildReadOnlyTextArea("AI Bridge will keep the long investigation notebook here as the case evolves.");
            this.chatTranscriptArea = buildReadOnlyTextArea("");
            this.chatInputArea = new JTextArea();
            this.statusLabel = new JLabel("Awaiting the first AI Bridge submission for this investigation.");
            this.submitButton = new JButton("Ask AI Bridge");
            this.transcriptEntries = new ArrayList<>();
            this.notebookEntries = new ArrayList<>();
            this.baselineRequest = "";
            this.followUpRunning = false;
            this.userRenamed = false;
            buildInvestigationWorkspace();
        }

        private void buildInvestigationWorkspace() {
            configureTextArea(requestArea, 220);
            requestArea.setLineWrap(true);
            requestArea.setWrapStyleWord(false);
            requestArea.setFont(CODE_FONT);

            responseArea.setRows(18);
            responseArea.setLineWrap(false);
            responseArea.setWrapStyleWord(false);
            responseArea.setFont(CODE_FONT);

            contextArea.setRows(12);
            contextArea.setFont(FORM_FONT);
            notebookArea.setRows(14);
            notebookArea.setFont(FORM_FONT);
            chatTranscriptArea.setRows(18);
            chatTranscriptArea.setFont(FORM_FONT.deriveFont(14f));
            configureTextArea(chatInputArea, 120);
            chatInputArea.setRows(6);
            chatInputArea.setFont(FORM_FONT.deriveFont(14f));

            JTabbedPane requestTabs = new JTabbedPane();
            requestTabs.addTab("Request Draft", wrapInvestigationArea(null, requestArea));
            requestTabs.addTab("Response Snapshot", wrapInvestigationArea(null, responseArea));
            requestTabs.addTab("Exact Changes", wrapInvestigationArea(
                    "AI Bridge extracts the next request edits and confirmation cues here.",
                    exactChangeArea
            ));
            requestTabs.addTab("Case Notebook", wrapInvestigationArea(
                    "AI Bridge carries the long-running case summary here so later follow-ups stay anchored to the same finding.",
                    notebookArea
            ));
            requestTabs.addTab("Evidence Context", wrapInvestigationArea(null, contextArea));

            JPanel leftActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
            JButton copyRequestButton = new JButton("Copy Request");
            copyRequestButton.addActionListener(ignored -> copyTextToClipboard(requestArea.getText(), "Request draft copied."));
            JButton copyResponseButton = new JButton("Copy Response");
            copyResponseButton.addActionListener(ignored -> copyTextToClipboard(responseArea.getText(), "Response snapshot copied."));
            JButton sendToRepeaterButton = new JButton("Send To Repeater");
            sendToRepeaterButton.addActionListener(ignored -> {
                if (investigationRepeaterSender != null) {
                    investigationRepeaterSender.accept(sessionId);
                } else {
                    statusLabel.setText("No Repeater sender is configured for this investigation.");
                }
            });
            JButton resetRequestButton = new JButton("Reset Request");
            resetRequestButton.addActionListener(ignored -> requestArea.setText(baselineRequest == null ? "" : baselineRequest));
            leftActions.add(copyRequestButton);
            leftActions.add(copyResponseButton);
            leftActions.add(sendToRepeaterButton);
            leftActions.add(resetRequestButton);

            JPanel leftPanel = new JPanel(new BorderLayout(8, 8));
            leftPanel.setBorder(BorderFactory.createTitledBorder("Request Workspace"));
            leftPanel.add(requestTabs, BorderLayout.CENTER);
            leftPanel.add(leftActions, BorderLayout.SOUTH);

            JPanel chatHeader = new JPanel(new BorderLayout(8, 4));
            JTextArea helper = buildHelperText(
                    "Ask for the next exact request change, the confirmation step for the Burp-marked issue, or the impact check to try after the last Repeater response."
            );
            helper.setRows(2);
            statusLabel.setForeground(HELPER_COLOR);
            chatHeader.add(helper, BorderLayout.NORTH);
            chatHeader.add(statusLabel, BorderLayout.SOUTH);

            JPanel chatActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
            JButton exactChangeButton = new JButton("Next Exact Change");
            exactChangeButton.addActionListener(ignored -> chatInputArea.setText(
                    "Name the exact next request change for this Burp-marked request. Keep the same insertion point if possible and tell me what to compare after sending it."
            ));
            JButton confirmFindingButton = new JButton("Confirm Finding");
            confirmFindingButton.addActionListener(ignored -> chatInputArea.setText(
                    "Use the existing Burp issue, Collaborator evidence, and latest response to tell me the next confirmation step in Repeater before expanding the test."
            ));
            JButton impactButton = new JButton("Check Impact");
            impactButton.addActionListener(ignored -> chatInputArea.setText(
                    "Assume the vulnerability is real. Tell me the safest next impact-oriented request change to confirm exploitability without broad fuzzing."
            ));
            JButton useInOperatorConsoleButton = new JButton("Use In Operator Console");
            useInOperatorConsoleButton.addActionListener(ignored -> {
                suggestionFollowUpArea.setText(chatInputArea.getText());
                workspaceTabs.setSelectedIndex(Math.min(WORKSPACE_TAB_EVIDENCE, workspaceTabs.getTabCount() - 1));
                selectResultsTab(RESULTS_TAB_AI_ANALYSIS);
            });
            JButton clearDraftButton = new JButton("Clear Draft");
            clearDraftButton.addActionListener(ignored -> chatInputArea.setText(""));
            submitButton.addActionListener(ignored -> submitInvestigationChat(sessionId));
            chatActions.add(exactChangeButton);
            chatActions.add(confirmFindingButton);
            chatActions.add(impactButton);
            chatActions.add(useInOperatorConsoleButton);
            chatActions.add(clearDraftButton);
            chatActions.add(submitButton);

            JPanel inputPanel = new JPanel(new BorderLayout(8, 8));
            inputPanel.setBorder(BorderFactory.createTitledBorder("AI Chat"));
            inputPanel.add(new JScrollPane(chatInputArea), BorderLayout.CENTER);
            inputPanel.add(chatActions, BorderLayout.SOUTH);

            JSplitPane rightSplit = new JSplitPane(
                    JSplitPane.VERTICAL_SPLIT,
                    wrapInvestigationArea(null, chatTranscriptArea),
                    inputPanel
            );
            rightSplit.setResizeWeight(0.80d);
            rightSplit.setDividerSize(8);
            rightSplit.setContinuousLayout(true);
            rightSplit.setOneTouchExpandable(true);

            JPanel rightPanel = new JPanel(new BorderLayout(8, 8));
            rightPanel.setBorder(BorderFactory.createTitledBorder("AI Interaction"));
            rightPanel.add(chatHeader, BorderLayout.NORTH);
            rightPanel.add(rightSplit, BorderLayout.CENTER);

            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
            splitPane.setResizeWeight(0.58d);
            splitPane.setDividerSize(8);
            splitPane.setContinuousLayout(true);
            splitPane.setOneTouchExpandable(true);

            root.add(splitPane, BorderLayout.CENTER);
        }
    }

    private JComponent wrapInvestigationArea(String helperText, JTextArea area) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        if (helperText != null && !helperText.isBlank()) {
            JTextArea helper = buildHelperText(helperText);
            panel.add(helper, BorderLayout.NORTH);
        }
        JScrollPane scrollPane = new JScrollPane(area);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.getHorizontalScrollBar().setUnitIncrement(16);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private static final class ScrollableStackPanel extends JPanel implements Scrollable {
        private ScrollableStackPanel() {
            super();
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 24;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return orientation == SwingConstants.VERTICAL
                    ? Math.max(visibleRect.height - 48, 48)
                    : Math.max(visibleRect.width - 48, 48);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    private JPanel buildFeedbackPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Result Feedback"));
        panel.setBackground(SUBTLE_PANEL);

        feedbackNotesField.putClientProperty("JTextField.placeholderText", "Optional note for future ranking, for example: helped prioritize csrf");
        feedbackStatusLabel.setForeground(HELPER_COLOR);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttons.add(usefulFeedbackButton);
        buttons.add(truePositiveFeedbackButton);
        buttons.add(notUsefulFeedbackButton);
        buttons.add(falsePositiveFeedbackButton);

        panel.add(feedbackStatusLabel, BorderLayout.NORTH);
        panel.add(feedbackNotesField, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    private JTextArea buildReadOnlyTextArea(String initialValue) {
        JTextArea textArea = new JTextArea(initialValue);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(NARRATIVE_FONT);
        textArea.setMargin(new Insets(8, 8, 8, 8));
        textArea.setBackground(Color.WHITE);
        return textArea;
    }

    private JTextField buildReadOnlyField(String value) {
        JTextField field = new JTextField(value);
        field.setEditable(false);
        field.setCaretPosition(0);
        return field;
    }

    private JPanel buildLabelValue(String labelText, JComponent valueComponent) {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        JLabel label = new JLabel(labelText);
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        panel.add(label, BorderLayout.NORTH);
        panel.add(valueComponent, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildChipRowPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        panel.setOpaque(false);
        return panel;
    }

    private void resetChipPanel(JPanel panel, String message) {
        panel.removeAll();
        panel.add(createChip(message, new Color(0xE9EFF7), new Color(0x175CD3)));
        panel.revalidate();
        panel.repaint();
    }

    private void refreshFindingChips(List<String> items) {
        findingChipsPanel.removeAll();
        List<String> source = items == null ? List.of() : items;
        if (source.isEmpty()) {
            resetChipPanel(findingChipsPanel, "No findings");
            return;
        }
        int count = 0;
        for (String item : source) {
            String text = compactChipText(item);
            if (text.isBlank()) {
                continue;
            }
            findingChipsPanel.add(createChip(text, severityChipBackground(text), severityChipForeground(text)));
            count++;
            if (count >= 4) {
                break;
            }
        }
        if (count == 0) {
            resetChipPanel(findingChipsPanel, "No findings");
            return;
        }
        findingChipsPanel.revalidate();
        findingChipsPanel.repaint();
    }

    private void refreshConfidenceChips(List<String> items) {
        confidenceChipsPanel.removeAll();
        List<String> source = items == null ? List.of() : items;
        if (source.isEmpty()) {
            resetChipPanel(confidenceChipsPanel, "No confidence");
            return;
        }
        int count = 0;
        for (String item : source) {
            String text = compactChipText(item);
            if (text.isBlank()) {
                continue;
            }
            confidenceChipsPanel.add(createChip(text, confidenceChipBackground(text), confidenceChipForeground(text)));
            count++;
            if (count >= 4) {
                break;
            }
        }
        if (count == 0) {
            resetChipPanel(confidenceChipsPanel, "No confidence");
            return;
        }
        confidenceChipsPanel.revalidate();
        confidenceChipsPanel.repaint();
    }

    private JLabel createChip(String text, Color background, Color foreground) {
        JLabel label = new JLabel(text);
        label.setOpaque(true);
        label.setBackground(background);
        label.setForeground(foreground);
        label.setBorder(new EmptyBorder(4, 8, 4, 8));
        return label;
    }

    private String compactChipText(String item) {
        if (item == null) {
            return "";
        }
        String normalized = item.trim().replace(System.lineSeparator(), " ");
        if (normalized.length() <= 42) {
            return normalized;
        }
        return normalized.substring(0, 39).trim() + "...";
    }

    private String compactScanBcheckEntry(String item) {
        if (item == null) {
            return "";
        }
        String normalized = item.trim().replace(System.lineSeparator(), " ");
        int whyIndex = normalized.indexOf(" | Why:");
        if (whyIndex > 0) {
            normalized = normalized.substring(0, whyIndex).trim();
        }
        if (normalized.length() <= 120) {
            return normalized;
        }
        return normalized.substring(0, 117).trim() + "...";
    }

    private String compactSingleLine(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        String normalized = value.trim().replace(System.lineSeparator(), " ");
        if (normalized.length() <= maxLength) {
            return normalized;
        }
        return normalized.substring(0, Math.max(0, maxLength - 3)).trim() + "...";
    }

    private Color severityChipBackground(String text) {
        String value = text == null ? "" : text.toLowerCase();
        if (value.contains("sqli") || value.contains("ssrf") || value.contains("command-injection")) {
            return new Color(0xFEE4E2);
        }
        if (value.contains("access-control") || value.contains("authentication") || value.contains("http-request-smuggling") || value.contains("deserialization")) {
            return new Color(0xFEEFC6);
        }
        if (value.contains("xss") || value.contains("csrf") || value.contains("path-traversal") || value.contains("mass-assignment")) {
            return new Color(0xFFF3B0);
        }
        return new Color(0xE9EFF7);
    }

    private Color severityChipForeground(String text) {
        String value = text == null ? "" : text.toLowerCase();
        if (value.contains("sqli") || value.contains("ssrf") || value.contains("command-injection")) {
            return new Color(0xB42318);
        }
        if (value.contains("access-control") || value.contains("authentication") || value.contains("http-request-smuggling") || value.contains("deserialization")) {
            return new Color(0x9A6700);
        }
        if (value.contains("xss") || value.contains("csrf") || value.contains("path-traversal") || value.contains("mass-assignment")) {
            return new Color(0xB54708);
        }
        return new Color(0x175CD3);
    }

    private Color confidenceChipBackground(String text) {
        String value = text == null ? "" : text.toLowerCase();
        if (value.contains("high")) {
            return new Color(0xD1FADF);
        }
        if (value.contains("medium")) {
            return new Color(0xFEF3C7);
        }
        if (value.contains("low")) {
            return new Color(0xF2F4F7);
        }
        return new Color(0xE9EFF7);
    }

    private Color confidenceChipForeground(String text) {
        String value = text == null ? "" : text.toLowerCase();
        if (value.contains("high")) {
            return new Color(0x027A48);
        }
        if (value.contains("medium")) {
            return new Color(0xB54708);
        }
        if (value.contains("low")) {
            return new Color(0x344054);
        }
        return new Color(0x175CD3);
    }

    private void renderQuestionInputs(List<String> questions) {
        questionsPanel.removeAll();
        questionInputs.clear();
        boolean hasQuestions = questions != null && !questions.isEmpty();
        questionSectionPanel.setVisible(hasQuestions);

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weightx = 1.0d;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.NORTHWEST;
        constraints.insets = new Insets(0, 0, 8, 0);

        if (hasQuestions) {
            for (String question : questions) {
                JPanel row = new JPanel(new BorderLayout(0, 6));
                JLabel questionLabel = new JLabel(question);
                JTextField answerField = new JTextField();
                answerField.putClientProperty("JTextField.placeholderText", "Type the operator constraint or answer here");
                answerField.getDocument().addDocumentListener(operatorInputListener());
                row.add(questionLabel, BorderLayout.NORTH);
                row.add(answerField, BorderLayout.CENTER);

                questionInputs.put(question, answerField);
                questionsPanel.add(row, constraints);
                constraints.gridy++;
            }
        }

        constraints.weighty = 1.0d;
        questionsPanel.add(Box.createVerticalGlue(), constraints);
        questionsPanel.revalidate();
        questionsPanel.repaint();
        questionSectionPanel.revalidate();
        questionSectionPanel.repaint();
    }

    private void clearAnswers() {
        for (JTextField textField : questionInputs.values()) {
            textField.setText("");
        }
    }

    private void configureFeedbackControls() {
        usefulFeedbackButton.addActionListener(ignored -> submitFeedback("useful"));
        truePositiveFeedbackButton.addActionListener(ignored -> submitFeedback("true_positive"));
        notUsefulFeedbackButton.addActionListener(ignored -> submitFeedback("not_useful"));
        falsePositiveFeedbackButton.addActionListener(ignored -> submitFeedback("false_positive"));
    }

    private void configureOperatorInputControls() {
        toolHelpArea.getDocument().addDocumentListener(operatorInputListener());
        refreshToolInventoryButton.addActionListener(ignored -> refreshToolInventory());
        scopeIncludesArea.getDocument().addDocumentListener(operatorInputListener());
        scopeExcludesArea.getDocument().addDocumentListener(operatorInputListener());
        rateLimitField.getDocument().addDocumentListener(operatorInputListener());
        maxConcurrencyField.getDocument().addDocumentListener(operatorInputListener());
        customHeadersArea.getDocument().addDocumentListener(operatorInputListener());
        responseDeltaArea.getDocument().addDocumentListener(operatorInputListener());
        programPolicyArea.getDocument().addDocumentListener(operatorInputListener());
        burpConfigExportArea.getDocument().addDocumentListener(operatorInputListener());
        burpScreenshotAuditArea.getDocument().addDocumentListener(operatorInputListener());
        savedLoadedBurpToolsArea.getDocument().addDocumentListener(operatorInputListener());
        savedProgramPolicyArea.getDocument().addDocumentListener(operatorInputListener());
        savedProgramScreenshotArea.getDocument().addDocumentListener(operatorInputListener());
        bappFindingsArea.getDocument().addDocumentListener(operatorInputListener());
        loggerEvidenceArea.getDocument().addDocumentListener(operatorInputListener());
        collaboratorEvidenceArea.getDocument().addDocumentListener(operatorInputListener());
        toolResultsArea.getDocument().addDocumentListener(operatorInputListener());
        suggestionFollowUpArea.getDocument().addDocumentListener(operatorInputListener());
        evidenceSourceField.getDocument().addDocumentListener(operatorInputListener());
        autoUseSavedSettingsCheckBox.addActionListener(ignored -> markOperatorInputCaptured());
        timeBudgetCombo.addActionListener(ignored -> {
            markOperatorInputCaptured();
            if (!jobWatchdogActive) {
                providerRouteField.setText(DEFAULT_PROVIDER_ROUTE.replace("Balanced", selectedTimeBudgetLabel()));
            }
        });
        syncCollaboratorButton.addActionListener(ignored -> syncCollaborator());
        rotateCollaboratorButton.addActionListener(ignored -> rotateCollaborator());
        copyCollaboratorPayloadButton.addActionListener(ignored ->
                copyTextToClipboard(collaboratorPayloadField.getText(), "Collaborator payload copied."));
        analyzeRecentScanButton.addActionListener(ignored -> analyzeRecentScanFindings());
        analyzeCurrentTargetScanButton.addActionListener(ignored -> analyzeCurrentTargetScanFindings());
        useCurrentTargetButton.addActionListener(ignored -> useCurrentTargetForScan());
        launchScanButton.addActionListener(ignored -> launchScan());
        copyNewScanHandoffButton.addActionListener(ignored ->
                copyTextToClipboard(
                        latestDetailedWorkflowText == null || latestDetailedWorkflowText.isBlank()
                                ? newScanHandoffArea.getText()
                                : latestDetailedWorkflowText,
                        "Burp workflow copied."
                ));
        addScanBcheckButton.addActionListener(ignored -> openBcheckCatalog());
        removeScanBcheckButton.addActionListener(ignored -> removeSelectedScanBchecks());
        clearScanBcheckButton.addActionListener(ignored -> clearScanBchecks());
        submitAnswersButton.addActionListener(ignored -> submitFollowUp());
        askSuggestionButton.addActionListener(ignored -> submitFollowUp());
        addEvidenceButton.addActionListener(ignored -> addEvidenceTimelineEntry());
        clearEvidenceButton.addActionListener(ignored -> clearEvidenceTimeline());
        addSkipClassButton.addActionListener(ignored -> addSkippedClass());
        removeSkipClassButton.addActionListener(ignored -> removeSelectedSkippedClasses());
        parseProgramRulesButton.addActionListener(ignored -> parseProgramRules());
        applyBurpSettingsButton.addActionListener(ignored -> applyBurpSettings());
        disableBurpSettingsButton.addActionListener(ignored -> disableBurpSettings());
        saveSettingsButton.addActionListener(ignored -> saveAiBridgeSettings());
        reloadSettingsButton.addActionListener(ignored -> reloadAiBridgeSettings());
        clearSettingsButton.addActionListener(ignored -> clearAiBridgeSettings());
        copyRequestPlanButton.addActionListener(ignored -> copyTextToClipboard(requestPlanArea.getText(), "Request plan copied."));
        copyCommandsButton.addActionListener(ignored -> copyTextToClipboard(kaliCommandsArea.getText(), "Kali commands copied."));
        copyPayloadsButton.addActionListener(ignored -> copyTextToClipboard(payloadListsArea.getText(), "Payload starter lists copied."));
        copyFullAdvisoryButton.addActionListener(ignored -> copyTextToClipboard(buildFullAdvisoryText(), "Full advisory copied."));
        resetSkipClassesButton.addActionListener(ignored -> {
            applyDefaultReviewScope();
            markOperatorInputCaptured();
        });
    }

    private InvestigationWorkspace ensureInvestigationWorkspace(String sessionId, String title) {
        InvestigationWorkspace existing = investigationWorkspaces.get(sessionId);
        if (existing != null) {
            return existing;
        }

        InvestigationWorkspace workspace = new InvestigationWorkspace(
                sessionId,
                title == null || title.isBlank() ? "Investigation" : title
        );
        workspace.submitButton.setEnabled(!workspace.followUpRunning);
        investigationWorkspaces.put(sessionId, workspace);
        investigationTabs.addTab(workspace.title, workspace.root);
        int tabIndex = investigationTabs.indexOfComponent(workspace.root);
        if (tabIndex >= 0) {
            investigationTabs.setTabComponentAt(tabIndex, buildInvestigationTabComponent(workspace));
        }
        investigationHintArea.setText(
                "Double-click a tab to rename it. Close tabs you do not need. Repeater can reuse the closest matching investigation."
        );
        return workspace;
    }

    private JComponent buildInvestigationTabComponent(InvestigationWorkspace workspace) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        panel.setOpaque(false);

        JLabel titleLabel = new JLabel(workspace.title);
        titleLabel.setBorder(new EmptyBorder(0, 0, 0, 2));

        JButton closeButton = new JButton("x");
        closeButton.setMargin(new Insets(0, 4, 0, 4));
        closeButton.setFocusable(false);
        closeButton.addActionListener(ignored -> closeInvestigation(workspace.sessionId));

        panel.add(titleLabel);
        panel.add(closeButton);
        return panel;
    }

    private void closeInvestigation(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.remove(sessionId);
        if (workspace == null) {
            return;
        }
        int tabIndex = investigationTabs.indexOfComponent(workspace.root);
        if (tabIndex >= 0) {
            investigationTabs.removeTabAt(tabIndex);
        }
        if (sessionId.equals(activeInvestigationId)) {
            activeInvestigationId = "";
            handleInvestigationSelectionChanged();
        }
        if (investigationCloseListener != null) {
            investigationCloseListener.accept(sessionId);
        }
    }

    private void selectInvestigation(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        if (workspace == null) {
            return;
        }
        activeInvestigationId = sessionId;
        investigationTabs.setSelectedComponent(workspace.root);
        workspaceTabs.setSelectedIndex(Math.min(WORKSPACE_TAB_INVESTIGATIONS, workspaceTabs.getTabCount() - 1));
        handleInvestigationSelectionChanged();
    }

    private void handleInvestigationSelectionChanged() {
        Component selected = investigationTabs.getSelectedComponent();
        if (selected == null) {
            activeInvestigationId = "";
            return;
        }
        InvestigationWorkspace workspace = findWorkspaceByComponent(selected);
        if (workspace == null) {
            activeInvestigationId = "";
            return;
        }
        activeInvestigationId = workspace.sessionId;
        if (workspace.request != null) {
            restoreOperatorInputs(workspace.request);
        }
        if (investigationSelectionListener != null) {
            investigationSelectionListener.accept(workspace.sessionId);
        }
    }

    private InvestigationWorkspace findWorkspaceByComponent(Component component) {
        for (InvestigationWorkspace workspace : investigationWorkspaces.values()) {
            if (workspace.root == component) {
                return workspace;
            }
        }
        return null;
    }

    private void promptRenameInvestigation(int index) {
        Component component = investigationTabs.getComponentAt(index);
        InvestigationWorkspace workspace = findWorkspaceByComponent(component);
        if (workspace == null) {
            return;
        }

        String nextTitle = JOptionPane.showInputDialog(
                mainPanel,
                "Rename this investigation",
                workspace.title,
                JOptionPane.PLAIN_MESSAGE
        );
        if (nextTitle == null) {
            return;
        }

        String trimmed = nextTitle.trim();
        if (trimmed.isBlank()) {
            return;
        }
        workspace.title = trimmed;
        workspace.userRenamed = true;
        int tabIndex = investigationTabs.indexOfComponent(component);
        if (tabIndex >= 0) {
            investigationTabs.setTitleAt(tabIndex, trimmed);
            investigationTabs.setTabComponentAt(tabIndex, buildInvestigationTabComponent(workspace));
        }
        if (investigationRenameListener != null) {
            investigationRenameListener.accept(workspace.sessionId, trimmed);
        }
    }

    private void submitInvestigationChat(String sessionId) {
        InvestigationWorkspace workspace = investigationWorkspaces.get(sessionId);
        if (workspace == null) {
            return;
        }
        if (workspace.followUpRunning) {
            workspace.statusLabel.setText("An AI follow-up is already running for this investigation. Wait for it before submitting again.");
            return;
        }
        String prompt = workspace.chatInputArea.getText().trim();
        if (prompt.isBlank()) {
            workspace.statusLabel.setText("Type a concrete request edit or follow-up question before submitting.");
            return;
        }
        if (investigationChatSubmitter == null) {
            workspace.statusLabel.setText("No AI Bridge chat submitter is configured.");
            return;
        }
        appendInvestigationTranscript(workspace, "operator", prompt);
        appendNotebookEntry(workspace, "operator_question", "Operator follow-up", prompt);
        workspace.chatInputArea.setText("");
        setInvestigationFollowUpRunning(workspace, true);
        workspace.statusLabel.setText("Submitting this follow-up to AI Bridge...");
        refreshInvestigationNotebook(workspace);
        investigationChatSubmitter.accept(sessionId, prompt);
    }

    private void setInvestigationFollowUpRunning(InvestigationWorkspace workspace, boolean running) {
        if (workspace == null) {
            return;
        }
        workspace.followUpRunning = running;
        workspace.submitButton.setEnabled(!running);
    }

    private void appendInvestigationTranscript(InvestigationWorkspace workspace, String speaker, String message) {
        if (workspace == null || message == null || message.isBlank()) {
            return;
        }
        String prefix = switch (speaker) {
            case "operator" -> "You";
            case "assistant" -> "AI Bridge";
            default -> "System";
        };
        String timestamp = timestampNow();
        workspace.transcriptEntries.add(new InvestigationTranscriptEntry(timestamp, prefix, message.trim()));
        if (!workspace.chatTranscriptArea.getText().isBlank()) {
            workspace.chatTranscriptArea.append(System.lineSeparator() + System.lineSeparator());
        }
        workspace.chatTranscriptArea.append("[" + timestamp + "] " + prefix + ":" + System.lineSeparator() + message.trim());
        workspace.chatTranscriptArea.setCaretPosition(workspace.chatTranscriptArea.getDocument().getLength());
    }

    private void ensureTranscriptEntriesLoaded(InvestigationWorkspace workspace) {
        if (workspace == null || !workspace.transcriptEntries.isEmpty() || workspace.chatTranscriptArea.getText().isBlank()) {
            return;
        }
        workspace.transcriptEntries.addAll(parseInvestigationTranscriptEntries(workspace.chatTranscriptArea.getText()));
    }

    private void ensureNotebookEntriesLoaded(InvestigationWorkspace workspace) {
        if (workspace == null || !workspace.notebookEntries.isEmpty()) {
            return;
        }
        rebuildLegacyNotebookEntries(workspace);
    }

    private void rebuildLegacyNotebookEntries(InvestigationWorkspace workspace) {
        if (workspace == null) {
            return;
        }
        workspace.notebookEntries.clear();
        String status = safeText(workspace.statusLabel.getText()).trim();
        if (!status.isBlank()) {
            appendNotebookEntry(workspace, "status", "Latest investigation status", status);
        }
        String exactChange = safeText(workspace.exactChangeArea.getText()).trim();
        if (!exactChange.isBlank()) {
            appendNotebookEntry(workspace, "exact_change", "Latest exact change summary", exactChange);
        }
        ensureTranscriptEntriesLoaded(workspace);
        for (InvestigationTranscriptEntry entry : workspace.transcriptEntries) {
            String kind = switch (entry.speakerLabel()) {
                case "You" -> "operator_question";
                case "AI Bridge" -> "assistant_guidance";
                default -> "system";
            };
            appendNotebookEntry(workspace, kind, entry.speakerLabel(), entry.message(), entry.timestamp());
        }
    }

    private List<InvestigationNotebookEntry> toNotebookEntries(List<InvestigationNotebookEntryState> notebookStates) {
        if (notebookStates == null || notebookStates.isEmpty()) {
            return List.of();
        }
        List<InvestigationNotebookEntry> entries = new ArrayList<>();
        for (InvestigationNotebookEntryState state : notebookStates) {
            if (state == null) {
                continue;
            }
            String title = safeText(state.title).trim();
            String details = safeText(state.details).trim();
            if (title.isBlank() && details.isBlank()) {
                continue;
            }
            entries.add(new InvestigationNotebookEntry(
                    safeText(state.timestamp).trim(),
                    safeText(state.kind).trim(),
                    title,
                    details
            ));
        }
        return entries;
    }

    private void appendNotebookEntry(InvestigationWorkspace workspace, String kind, String title, String details) {
        appendNotebookEntry(workspace, kind, title, details, timestampNow());
    }

    private void appendNotebookEntry(InvestigationWorkspace workspace, String kind, String title, String details, String timestamp) {
        if (workspace == null) {
            return;
        }
        String normalizedTitle = safeText(title).trim();
        String normalizedDetails = safeText(details).trim();
        if (normalizedTitle.isBlank() && normalizedDetails.isBlank()) {
            return;
        }
        String normalizedTimestamp = safeText(timestamp).trim();
        InvestigationNotebookEntry next = new InvestigationNotebookEntry(
                normalizedTimestamp.isBlank() ? timestampNow() : normalizedTimestamp,
                safeText(kind).trim(),
                normalizedTitle,
                normalizedDetails
        );
        if (!workspace.notebookEntries.isEmpty()) {
            InvestigationNotebookEntry last = workspace.notebookEntries.get(workspace.notebookEntries.size() - 1);
            if (last.kind().equals(next.kind())
                    && last.title().equals(next.title())
                    && last.details().equals(next.details())) {
                return;
            }
        }
        workspace.notebookEntries.add(next);
    }

    private void refreshInvestigationNotebook(InvestigationWorkspace workspace) {
        if (workspace == null) {
            return;
        }
        workspace.notebookArea.setText(buildInvestigationCaseNotebook(workspace));
        workspace.notebookArea.setCaretPosition(0);
    }

    private String buildInvestigationCaseNotebook(InvestigationWorkspace workspace) {
        if (workspace == null) {
            return "No investigation notebook yet.";
        }
        ensureNotebookEntriesLoaded(workspace);

        List<String> lines = new ArrayList<>();
        lines.add("Investigation anchor");
        if (workspace.request != null) {
            lines.add("- Source: " + safeText(requestOriginLabel(workspace.request)));
            lines.add("- Target: " + safeText(workspace.request.getTargetUrl()));
            lines.add("- Method: " + safeText(requestMethodLabel(workspace.request)));
        }
        String status = compactSingleLine(workspace.statusLabel.getText(), 220);
        if (!status.isBlank()) {
            lines.add("- Latest status: " + status);
        }
        String exactChange = safeText(workspace.exactChangeArea.getText()).trim();
        if (!exactChange.isBlank()) {
            lines.add("- Current exact change summary: " + compactSingleLine(exactChange, 420));
        }

        lines.add("");
        lines.add("Persistent notebook timeline");
        int maxEntries = 18;
        if (workspace.notebookEntries.size() > maxEntries) {
            lines.add("- ... " + (workspace.notebookEntries.size() - maxEntries) + " earlier notebook item(s) omitted from this compact view.");
        }
        int startIndex = Math.max(0, workspace.notebookEntries.size() - maxEntries);
        for (int index = startIndex; index < workspace.notebookEntries.size(); index++) {
            InvestigationNotebookEntry entry = workspace.notebookEntries.get(index);
            String title = entry.title().isBlank() ? "Notebook entry" : entry.title();
            String details = compactSingleLine(entry.details(), 420);
            StringBuilder line = new StringBuilder();
            line.append("- [").append(entry.timestamp()).append("] ").append(title);
            if (!details.isBlank()) {
                line.append(": ").append(details);
            }
            lines.add(line.toString());
        }

        return String.join(System.lineSeparator(), lines).trim();
    }

    private String buildNotebookAssistantSummary(AdvisoryResponse response, String exactChangeSummary) {
        if (response == null) {
            return safeText(exactChangeSummary);
        }
        List<String> notes = new ArrayList<>();
        String primary = compactSingleLine(response.getPrimaryNextAction(), 260);
        if (!primary.isBlank()) {
            notes.add("Primary next action: " + primary);
        }
        String exact = compactSingleLine(exactChangeSummary, 420);
        if (!exact.isBlank()) {
            notes.add("Exact change summary: " + exact);
        }
        List<String> suggestionQueue = response.getSuggestionQueue() == null ? List.of() : response.getSuggestionQueue();
        if (!suggestionQueue.isEmpty()) {
            notes.add("Next exact check: " + compactSingleLine(suggestionQueue.get(0), 260));
        }
        return String.join(System.lineSeparator(), notes).trim();
    }

    private List<InvestigationTranscriptEntry> toTranscriptEntries(List<InvestigationTranscriptState> transcriptStates) {
        if (transcriptStates == null || transcriptStates.isEmpty()) {
            return List.of();
        }
        List<InvestigationTranscriptEntry> entries = new ArrayList<>();
        for (InvestigationTranscriptState state : transcriptStates) {
            if (state == null) {
                continue;
            }
            String timestamp = safeText(state.timestamp).trim();
            String speaker = safeText(state.speaker).trim();
            String message = safeText(state.message).trim();
            if (!speaker.isBlank() && !message.isBlank()) {
                entries.add(new InvestigationTranscriptEntry(timestamp, speaker, message));
            }
        }
        return entries;
    }

    private List<InvestigationTranscriptEntry> parseInvestigationTranscriptEntries(String transcript) {
        String value = safeText(transcript);
        if (value.isBlank()) {
            return List.of();
        }

        List<InvestigationTranscriptEntry> entries = new ArrayList<>();
        Matcher matcher = INVESTIGATION_TRANSCRIPT_HEADER_PATTERN.matcher(value);
        String currentTimestamp = "";
        String currentSpeaker = "";
        int messageStart = -1;
        while (matcher.find()) {
            if (messageStart >= 0) {
                String message = value.substring(messageStart, matcher.start()).trim();
                if (!message.isBlank()) {
                    entries.add(new InvestigationTranscriptEntry(currentTimestamp, currentSpeaker, message));
                }
            }
            currentTimestamp = matcher.group(1);
            currentSpeaker = matcher.group(2);
            messageStart = matcher.end();
        }
        if (messageStart >= 0) {
            String message = value.substring(messageStart).trim();
            if (!message.isBlank()) {
                entries.add(new InvestigationTranscriptEntry(currentTimestamp, currentSpeaker, message));
            }
        }
        return entries;
    }

    private String buildInvestigationTranscript(List<InvestigationTranscriptEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (InvestigationTranscriptEntry entry : entries) {
            if (builder.length() > 0) {
                builder.append(System.lineSeparator()).append(System.lineSeparator());
            }
            String timestamp = entry.timestamp() == null || entry.timestamp().isBlank() ? timestampNow() : entry.timestamp();
            builder.append("[").append(timestamp).append("] ")
                    .append(entry.speakerLabel())
                    .append(":")
                    .append(System.lineSeparator())
                    .append(entry.message());
        }
        return builder.toString();
    }

    private String buildInvestigationContext(AssessmentRequest request) {
        if (request == null) {
            return "No investigation context yet.";
        }

        List<String> lines = new ArrayList<>();
        lines.add("Source: " + safeText(requestOriginLabel(request)));
        lines.add("Target: " + safeText(request.getTargetUrl()));
        lines.add("Method: " + safeText(requestMethodLabel(request)));
        if (!request.getAnnotations().isEmpty()) {
            lines.add("Annotations: " + String.join(", ", request.getAnnotations()));
        }
        if (request.getToolResultsText() != null && !request.getToolResultsText().isBlank()) {
            lines.add("");
            lines.add("Burp issue summary:");
            lines.add(request.getToolResultsText().trim());
        }
        if (request.getBappFindingsText() != null && !request.getBappFindingsText().isBlank()) {
            lines.add("");
            lines.add("BApp or scanner correlation:");
            lines.add(request.getBappFindingsText().trim());
        }
        if (request.getCollaboratorEvidenceText() != null && !request.getCollaboratorEvidenceText().isBlank()) {
            lines.add("");
            lines.add("Collaborator evidence:");
            lines.add(request.getCollaboratorEvidenceText().trim());
        }
        return String.join(System.lineSeparator(), lines);
    }

    private String buildInvestigationReply(AdvisoryResponse response) {
        if (response == null) {
            return "No advisory response was returned.";
        }

        StringBuilder builder = new StringBuilder();
        builder.append("Primary next action: ").append(response.getPrimaryNextAction()).append(System.lineSeparator());
        List<String> requestPlan = response.getRequestPlan() == null ? List.of() : response.getRequestPlan();
        if (!requestPlan.isEmpty()) {
            builder.append(System.lineSeparator()).append("Recommended request workflow:");
            for (String item : requestPlan.subList(0, Math.min(4, requestPlan.size()))) {
                builder.append(System.lineSeparator()).append("- ").append(item);
            }
        }
        List<String> confirmationPlaybooks = response.getConfirmationPlaybooks() == null ? List.of() : response.getConfirmationPlaybooks();
        if (!confirmationPlaybooks.isEmpty()) {
            builder.append(System.lineSeparator()).append(System.lineSeparator()).append("Confirmation playbook:");
            for (String item : confirmationPlaybooks.subList(0, Math.min(3, confirmationPlaybooks.size()))) {
                builder.append(System.lineSeparator()).append("- ").append(item);
            }
        }
        String visibleAnalysis = summarizeInvestigationAnalysis(operatorVisibleAnalysis(response.getAnalysis()));
        if (!visibleAnalysis.isBlank()) {
            builder.append(System.lineSeparator()).append(System.lineSeparator());
            builder.append(visibleAnalysis);
        }
        List<String> suggestionQueue = response.getSuggestionQueue() == null ? List.of() : response.getSuggestionQueue();
        if (!suggestionQueue.isEmpty()) {
            builder.append(System.lineSeparator()).append(System.lineSeparator()).append("Next exact checks:");
            for (String item : suggestionQueue.subList(0, Math.min(4, suggestionQueue.size()))) {
                builder.append(System.lineSeparator()).append("- ").append(item);
            }
        }
        return builder.toString().trim();
    }

    private String summarizeInvestigationAnalysis(String text) {
        String normalized = safeText(text).replace("\r\n", "\n").trim();
        if (normalized.isBlank()) {
            return "";
        }

        List<String> kept = new ArrayList<>();
        int nonBlankCount = 0;
        for (String rawLine : normalized.split("\n")) {
            String trimmed = rawLine.trim();
            if (trimmed.isBlank()) {
                if (!kept.isEmpty() && !kept.get(kept.size() - 1).isBlank()) {
                    kept.add("");
                }
                continue;
            }
            if (trimmed.startsWith("Profile:")
                    || trimmed.startsWith("Review scope classes:")
                    || trimmed.startsWith("Model:")
                    || trimmed.startsWith("Complexity estimate:")
                    || trimmed.startsWith("Suggested Kali WSL tools")
                    || trimmed.startsWith("Burp scan or BApp findings")
                    || trimmed.startsWith("Matched VA playbooks based on deterministic signals:")
                    || trimmed.startsWith("Program context notes:")
                    || trimmed.startsWith("Prior local memory:")
                    || trimmed.startsWith("Model refinement unavailable:")
                    || trimmed.startsWith("Manual tool results or file references were supplied")) {
                continue;
            }
            kept.add(trimmed.length() > 220 ? trimmed.substring(0, 217) + "..." : trimmed);
            nonBlankCount++;
            if (nonBlankCount >= 6) {
                break;
            }
        }
        while (!kept.isEmpty() && kept.get(kept.size() - 1).isBlank()) {
            kept.remove(kept.size() - 1);
        }
        return String.join(System.lineSeparator(), kept).trim();
    }

    private String buildExactChangeSummary(AdvisoryResponse response) {
        if (response == null) {
            return "No exact request changes available.";
        }

        StringBuilder builder = new StringBuilder();
        String primary = safeText(response.getPrimaryNextAction()).trim();
        if (!primary.isBlank()) {
            builder.append("Primary move").append(System.lineSeparator())
                    .append(primary);
        }

        List<String> requestPlan = response.getRequestPlan() == null ? List.of() : response.getRequestPlan();
        if (!requestPlan.isEmpty()) {
            if (builder.length() > 0) {
                builder.append(System.lineSeparator()).append(System.lineSeparator());
            }
            builder.append("Exact request changes");
            for (String item : requestPlan.subList(0, Math.min(4, requestPlan.size()))) {
                builder.append(System.lineSeparator()).append("- ").append(item);
            }
        }

        List<String> suggestionQueue = response.getSuggestionQueue() == null ? List.of() : response.getSuggestionQueue();
        if (!suggestionQueue.isEmpty()) {
            if (builder.length() > 0) {
                builder.append(System.lineSeparator()).append(System.lineSeparator());
            }
            builder.append("What to compare");
            for (String item : suggestionQueue.subList(0, Math.min(3, suggestionQueue.size()))) {
                builder.append(System.lineSeparator()).append("- ").append(item);
            }
        }

        return builder.length() == 0
                ? "AI Bridge did not return a compact exact-change summary for this investigation yet."
                : builder.toString().trim();
    }

    private String extractExactChangeSummaryFromTranscript(String transcript) {
        String text = safeText(transcript).trim();
        if (text.isBlank()) {
            return "No exact request changes saved yet for this investigation.";
        }
        if (text.contains("Primary next action:")) {
            String[] parts = text.split("Primary next action:");
            return "Restored exact-change summary" + System.lineSeparator()
                    + parts[parts.length - 1].trim();
        }
        return "Conversation restored. Ask AI Bridge for the next exact request change if you want a fresh summary.";
    }

    private String defaultInvestigationPrompt(AssessmentRequest request, AdvisoryResponse response) {
        String target = request == null ? "this request" : shortTargetLabel(request.getTargetUrl());
        String nextAction = response == null ? "" : safeText(response.getPrimaryNextAction()).trim();
        if (!nextAction.isBlank()) {
            return "For " + target + ", convert the primary next action into the exact next request change I should make in Repeater. "
                    + "Keep the Burp-marked insertion point aligned and tell me what response delta or Collaborator result to compare.";
        }
        return "Name the exact next request change for " + target + ". Keep the same insertion point if possible and tell me what to compare after sending it.";
    }

    private String fallbackInvestigationTitle(AssessmentRequest request) {
        return request == null ? "Investigation" : safeText(requestOriginLabel(request)) + " - " + shortTargetLabel(request.getTargetUrl());
    }

    private String shortTargetLabel(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return "unknown-target";
        }
        int schemeIndex = targetUrl.indexOf("://");
        String trimmed = schemeIndex >= 0 ? targetUrl.substring(schemeIndex + 3) : targetUrl;
        int slashIndex = trimmed.indexOf('/');
        return slashIndex >= 0 ? trimmed.substring(slashIndex) : trimmed;
    }

    private String safeText(String value) {
        return value == null ? "" : value;
    }

    private String operatorVisibleAnalysis(String text) {
        String normalized = safeText(text).replace("\r\n", "\n").trim();
        if (normalized.isBlank()) {
            return "";
        }

        int executionIndex = normalized.indexOf("Model execution:");
        if (executionIndex >= 0) {
            int nextSection = normalized.indexOf("\n\n", executionIndex);
            if (nextSection > executionIndex) {
                normalized = (normalized.substring(0, executionIndex) + normalized.substring(nextSection + 2)).trim();
            } else {
                normalized = normalized.substring(0, executionIndex).trim();
            }
        }

        List<String> kept = new ArrayList<>();
        for (String rawLine : normalized.split("\n")) {
            String line = rawLine.stripTrailing();
            String trimmed = line.trim();
            if (trimmed.startsWith("- REQUEST INFO:")
                    || trimmed.startsWith("- DETERMINISTIC READY:")
                    || trimmed.startsWith("- MCP FAILED:")
                    || trimmed.startsWith("- OLLAMA FAILED:")) {
                continue;
            }
            kept.add(line);
        }
        return String.join(System.lineSeparator(), kept).trim();
    }

    private void copyAnswersToClipboard() {
        try {
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(operatorAnswersForSubmission());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(json), null);
            setStatus("Operator answers copied to the clipboard.", new Color(0x2D7D46));
        } catch (JsonProcessingException exception) {
            showError("Unable to serialize operator answers: " + exception.getMessage());
        }
    }

    private void copyTextToClipboard(String text, String statusMessage) {
        String value = text == null ? "" : text.trim();
        if (value.isBlank()) {
            setStatus("Nothing to copy yet.", new Color(0xB54708));
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(value), null);
        setStatus(statusMessage, new Color(0x2D7D46));
    }

    private String buildFullAdvisoryText() {
        return String.join(
                System.lineSeparator() + System.lineSeparator(),
                "Primary Next Action: " + primaryNextActionField.getText(),
                "Request Plan:" + System.lineSeparator() + requestPlanArea.getText(),
                "Potential Vulnerabilities:" + System.lineSeparator() + vulnerabilitiesArea.getText(),
                "Kali Tools:" + System.lineSeparator() + kaliToolsArea.getText(),
                "Kali Commands:" + System.lineSeparator() + kaliCommandsArea.getText(),
                "Payload Lists:" + System.lineSeparator() + payloadListsArea.getText(),
                "Project Readiness:" + System.lineSeparator() + projectReadinessField.getText(),
                "Project Readiness Checks:" + System.lineSeparator() + projectReadinessArea.getText(),
                "Burp Action Checklist:" + System.lineSeparator() + burpActionChecklistArea.getText(),
                "Impact Paths:" + System.lineSeparator() + impactPathsArea.getText(),
                "Burp Settings:" + System.lineSeparator() + burpSettingsArea.getText(),
                "Loaded Burp Tools / BApps:" + System.lineSeparator() + savedLoadedBurpToolsArea.getText(),
                "Burp Config Export Audit Input:" + System.lineSeparator() + burpConfigExportArea.getText(),
                "Burp Screenshot Audit Input:" + System.lineSeparator() + burpScreenshotAuditArea.getText(),
                "Saved Program Rules:" + System.lineSeparator() + savedProgramPolicyArea.getText(),
                "Saved Program Screenshot Input:" + System.lineSeparator() + savedProgramScreenshotArea.getText(),
                "HTTP Logger Evidence:" + System.lineSeparator() + loggerEvidenceArea.getText(),
                "Suggestion Queue:" + System.lineSeparator() + suggestionQueueArea.getText(),
                "AI Analysis:" + System.lineSeparator() + analysisArea.getText()
        ).trim();
    }

    private void appendSelectedSuggestionToFollowUp() {
        String selected = suggestionQueueArea.getSelectedText();
        String queueText = selected == null || selected.isBlank() ? suggestionQueueArea.getText().trim() : selected.trim();
        if (queueText.isBlank() || queueText.startsWith("No ")) {
            setFollowUpStatus(
                    "No suggestion text is available yet. Wait for the advisory response to finish first.",
                    "No suggestion text is available yet. Wait for the advisory response to finish first."
            );
            return;
        }

        String existing = suggestionFollowUpArea.getText().trim();
        String builder = existing.isBlank()
                ? queueText
                : existing + System.lineSeparator() + System.lineSeparator() + queueText;
        suggestionFollowUpArea.setText(builder);
        suggestionFollowUpArea.setCaretPosition(0);
        setFollowUpStatus(
                "Suggestion text copied into the AI follow-up box. Add your parameter or payload question, then click 'Ask AI Follow-Up'.",
                "Suggestion text copied in. Add the exact parameter or payload question, then click 'Ask AI Follow-Up'."
        );
    }

    private String buildProgressText(AnalysisJobStatus status) {
        StringBuilder builder = new StringBuilder();
        builder.append("Job ID: ").append(status.getJobId()).append(System.lineSeparator()).append(System.lineSeparator());
        builder.append("Status: ").append(status.getStatus()).append(System.lineSeparator());
        builder.append("Estimated Duration: ").append(status.getEstimatedDuration()).append(System.lineSeparator());
        builder.append("Complexity: ").append(status.getComplexity()).append(System.lineSeparator()).append(System.lineSeparator());
        builder.append("Update: ").append(status.getStatusMessage()).append(System.lineSeparator()).append(System.lineSeparator());
        builder.append("Recommendation: ").append(status.getRecommendation());
        return builder.toString();
    }

    private String buildPendingProviderRoute(AssessmentRequest request) {
        return "Context: Burp MCP | Reasoning: local AI | Time budget: "
                + selectedTimeBudgetLabel()
                + " | Source: "
                + requestOriginLabel(request);
    }

    private String buildRunningProviderRoute(AssessmentRequest request, AnalysisJobStatus status) {
        StringBuilder builder = new StringBuilder(buildPendingProviderRoute(request));
        String eta = status == null ? "" : status.getEstimatedDuration();
        if (eta != null && !eta.isBlank() && !"unknown".equalsIgnoreCase(eta)) {
            builder.append(" | ETA ").append(eta);
        }
        return builder.toString();
    }

    private String buildCompletedProviderRoute(AdvisoryResponse response, AssessmentRequest request) {
        String backend = response == null ? "" : response.getAnalysisBackend().trim();
        String model = extractRoutedModel(response == null ? "" : response.getModelExecutionSummary());
        StringBuilder builder = new StringBuilder("Context: Burp MCP | Reasoning: ");
        builder.append(backend.isBlank() ? "local AI" : backend);
        if (!model.isBlank()) {
            builder.append(" | Model: ").append(model);
        }
        builder.append(" | Time budget: ").append(selectedTimeBudgetLabel());
        builder.append(" | Source: ").append(requestOriginLabel(request));
        return builder.toString();
    }

    private String extractRoutedModel(String executionSummary) {
        String text = executionSummary == null ? "" : executionSummary.trim();
        if (text.isBlank()) {
            return "";
        }
        Matcher matcher = ROUTED_MODEL_PATTERN.matcher(text);
        if (!matcher.find()) {
            return "";
        }
        String value = matcher.group(1);
        if (value == null) {
            return "";
        }
        return value.replaceAll("[,;]+$", "").trim();
    }

    private String statusLabelText(AnalysisJobStatus status) {
        String eta = status.getEstimatedDuration();
        String etaSuffix = eta == null || eta.isBlank() || "unknown".equalsIgnoreCase(eta)
                ? ""
                : " ETA: " + eta;
        return switch (status.getStatus()) {
            case "queued" -> "Analysis queued." + etaSuffix;
            case "running" -> "Analysis running." + etaSuffix;
            case "completed" -> "Advisory response ready.";
            case "failed" -> "Bridge request failed.";
            default -> "Analysis update received.";
        };
    }

    private void ensureResultsVisible() {
        if (workspaceTabs.getTabCount() > 0) {
            workspaceTabs.setSelectedIndex(Math.min(WORKSPACE_TAB_ADVISORY, workspaceTabs.getTabCount() - 1));
        }
    }

    private void setStatus(String text, Color color) {
        statusLabel.setText(text);
        statusLabel.setForeground(color);
    }

    private void startJobWatchdog() {
        jobWatchdogActive = true;
        stuckWarningShown = false;
        lastJobUpdateAtMillis = System.currentTimeMillis();
    }

    private void refreshJobWatchdog() {
        startJobWatchdog();
    }

    private void stopJobWatchdog() {
        jobWatchdogActive = false;
        stuckWarningShown = false;
        lastJobUpdateAtMillis = 0L;
    }

    private void maybeWarnAboutSlowJob() {
        if (!jobWatchdogActive || stuckWarningShown || lastJobUpdateAtMillis <= 0L) {
            return;
        }
        long elapsed = System.currentTimeMillis() - lastJobUpdateAtMillis;
        if (elapsed < STUCK_JOB_WARNING_MILLIS) {
            return;
        }
        stuckWarningShown = true;
        long seconds = Math.max(1L, elapsed / 1000L);
        setStatus(
                "No bridge update for " + seconds + "s. Likely a slow local model, provider timeout, or stopped bridge server.",
                new Color(0xB54708)
        );
        providerRouteField.setText(providerRouteField.getText() + " | Waiting on local model/server");
        if (estimatedDurationField.getText() == null
                || estimatedDurationField.getText().isBlank()
                || "Estimating...".equalsIgnoreCase(estimatedDurationField.getText())) {
            estimatedDurationField.setText("Taking longer than expected");
        }
    }

    private void submitFeedback(String label) {
        if (feedbackSubmitter == null) {
            feedbackStatusLabel.setText("No feedback handler is configured.");
            return;
        }
        if (currentJobId == null || currentJobId.isBlank()) {
            feedbackStatusLabel.setText("Feedback is unavailable because no completed job is selected.");
            return;
        }

        setFeedbackButtonsEnabled(false);
        feedbackStatusLabel.setText("Submitting feedback: " + label + "...");
        feedbackSubmitter.accept(label, feedbackNotesField.getText().trim());
    }

    private void enableFeedback(String statusText) {
        feedbackStatusLabel.setText(statusText);
        feedbackNotesField.setEnabled(true);
        setFeedbackButtonsEnabled(true);
    }

    private void disableFeedback(String statusText) {
        feedbackStatusLabel.setText(statusText);
        feedbackNotesField.setText("");
        feedbackNotesField.setEnabled(false);
        setFeedbackButtonsEnabled(false);
    }

    private void setFeedbackButtonsEnabled(boolean enabled) {
        usefulFeedbackButton.setEnabled(enabled);
        truePositiveFeedbackButton.setEnabled(enabled);
        notUsefulFeedbackButton.setEnabled(enabled);
        falsePositiveFeedbackButton.setEnabled(enabled);
    }

    private void submitFollowUp() {
        if (followUpSubmitter == null) {
            setFollowUpStatus("No follow-up handler is configured.", "No follow-up handler is configured.");
            return;
        }
        if (!hasMeaningfulOperatorContext()) {
            setFollowUpStatus(
                    "Type at least one answer, suggestion follow-up, program constraint, or tool result before submitting.",
                    "Add some queue text, a parameter question, or other operator context before submitting."
            );
            return;
        }
        showFollowUpSubmitting();
        followUpSubmitter.run();
    }

    private void refreshToolInventory() {
        if (toolInventoryRefresher == null) {
            showToolInventoryError("No tool inventory handler is configured.");
            return;
        }
        showToolInventoryLoading();
        toolInventoryRefresher.run();
    }

    private void syncCollaborator() {
        if (collaboratorSyncer == null) {
            showCollaboratorSyncError("No Collaborator sync handler is configured.");
            return;
        }
        showCollaboratorSyncLoading();
        collaboratorSyncer.run();
    }

    private void rotateCollaborator() {
        if (collaboratorRotator == null) {
            showCollaboratorSyncError("No Collaborator rotation handler is configured.");
            return;
        }
        showCollaboratorSyncLoading();
        collaboratorRotator.run();
    }

    private void analyzeRecentScanFindings() {
        if (recentScanAnalyzer == null) {
            showScanBridgeState(
                    scanBridgeSummaryArea.getText(),
                    "No recent scan analysis handler is configured.",
                    true,
                    true
            );
            return;
        }
        showScanBridgeState(
                scanBridgeSummaryArea.getText(),
                "Submitting recent Burp scan findings to AI Bridge...",
                true,
                true
        );
        recentScanAnalyzer.run();
    }

    private void analyzeCurrentTargetScanFindings() {
        if (currentTargetScanAnalyzer == null) {
            showScanBridgeState(
                    scanBridgeSummaryArea.getText(),
                    "No current-target scan analysis handler is configured.",
                    true,
                    true
            );
            return;
        }
        showScanBridgeState(
                scanBridgeSummaryArea.getText(),
                "Submitting current-target Burp scan findings to AI Bridge...",
                true,
                true
        );
        currentTargetScanAnalyzer.run();
    }

    private void useCurrentTargetForScan() {
        String currentTarget = targetLabel.getText() == null ? "" : targetLabel.getText().trim();
        if (currentTarget.isBlank() || currentTarget.startsWith("No request submitted")) {
            showScanLaunchStatus("No current target is loaded yet. Analyze a request first or type the target URL manually.");
            return;
        }
        scanTargetField.setText(currentTarget);
        scanTargetField.setCaretPosition(0);
        showScanLaunchStatus("Current advisory target copied into the scan launcher.");
    }

    private void launchScan() {
        if (scanLauncher == null) {
            showScanLaunchStatus("No scan launcher is configured.");
            return;
        }

        String targetUrl = scanTargetField.getText().trim();
        if (targetUrl.isBlank()) {
            showScanLaunchStatus("Type a target URL first.");
            return;
        }

        Object scanType = scanTypeCombo.getSelectedItem();
        Object auditConfiguration = auditConfigurationCombo.getSelectedItem();
        showScanLaunchStarting();
        scanLauncher.accept(new ScanLaunchRequest(
                targetUrl,
                scanType == null ? "" : scanType.toString(),
                auditConfiguration == null ? "" : auditConfiguration.toString(),
                selectedScanBchecks()
        ));
    }

    private void openBcheckCatalog() {
        if (bcheckCatalogOpener == null) {
            showScanLaunchStatus("No BCheck catalog loader is configured.");
            return;
        }
        showBcheckCatalogLoading();
        bcheckCatalogOpener.run();
    }

    private void removeSelectedScanBchecks() {
        List<String> selected = scanLaunchBcheckList.getSelectedValuesList();
        if (selected.isEmpty()) {
            showScanLaunchStatus("Select at least one BCheck checklist entry to remove.");
            return;
        }
        for (String item : selected) {
            scanLaunchBcheckModel.removeElement(item);
        }
        showScanLaunchStatus("Removed selected BCheck checklist entries.");
    }

    private void clearScanBchecks() {
        scanLaunchBcheckModel.clear();
        showScanLaunchStatus("Cleared the pre-launch BCheck checklist.");
    }

    private void refreshScanLaunchBchecks(List<String> recommendations) {
        scanLaunchBcheckModel.clear();
        if (recommendations == null) {
            return;
        }
        for (String recommendation : recommendations) {
            addScanBcheckEntry(recommendation, false);
        }
        if (!scanLaunchBcheckModel.isEmpty()) {
            scanLaunchBcheckList.setSelectionInterval(0, scanLaunchBcheckModel.size() - 1);
        }
    }

    private void addScanBcheckEntry(String entry, boolean selectNewItem) {
        String normalized = compactScanBcheckEntry(entry);
        if (normalized.isBlank()) {
            return;
        }
        for (int index = 0; index < scanLaunchBcheckModel.size(); index++) {
            if (normalized.equalsIgnoreCase(scanLaunchBcheckModel.get(index))) {
                if (selectNewItem) {
                    scanLaunchBcheckList.setSelectedIndex(index);
                }
                return;
            }
        }
        scanLaunchBcheckModel.addElement(normalized);
        if (selectNewItem) {
            int lastIndex = scanLaunchBcheckModel.size() - 1;
            scanLaunchBcheckList.setSelectedIndex(lastIndex);
            scanLaunchBcheckList.ensureIndexIsVisible(lastIndex);
        }
    }

    private List<String> selectedScanBchecks() {
        List<String> selected = new ArrayList<>(scanLaunchBcheckList.getSelectedValuesList());
        if (!selected.isEmpty()) {
            return List.copyOf(selected);
        }
        if (scanLaunchBcheckModel.isEmpty()) {
            return List.of();
        }
        for (int index = 0; index < scanLaunchBcheckModel.size(); index++) {
            selected.add(scanLaunchBcheckModel.getElementAt(index));
        }
        return List.copyOf(selected);
    }

    private void cancelFollowUp() {
        if (followUpCanceler == null) {
            setFollowUpStatus("No cancel handler is configured.", "No cancel handler is configured.");
            return;
        }
        followUpCanceler.run();
    }

    private void setFollowUpEnabled(boolean enabled) {
        submitAnswersButton.setEnabled(enabled);
        askSuggestionButton.setEnabled(enabled);
        skipClassCombo.setEnabled(enabled);
        skippedScopeList.setEnabled(enabled);
        addSkipClassButton.setEnabled(enabled);
        removeSkipClassButton.setEnabled(enabled);
        resetSkipClassesButton.setEnabled(enabled);
        parseProgramRulesButton.setEnabled(enabled);
        toolHelpArea.setEnabled(enabled);
        scopeIncludesArea.setEnabled(enabled);
        scopeExcludesArea.setEnabled(enabled);
        rateLimitField.setEnabled(enabled);
        maxConcurrencyField.setEnabled(enabled);
        customHeadersArea.setEnabled(enabled);
        programPolicyArea.setEnabled(enabled);
        burpConfigExportArea.setEnabled(enabled);
        burpScreenshotAuditArea.setEnabled(enabled);
        bappFindingsArea.setEnabled(enabled);
        loggerEvidenceArea.setEnabled(enabled);
        collaboratorEvidenceArea.setEnabled(enabled);
        toolResultsArea.setEnabled(enabled);
        suggestionFollowUpArea.setEnabled(enabled);
        evidenceSourceField.setEnabled(enabled);
        addEvidenceButton.setEnabled(enabled);
        clearEvidenceButton.setEnabled(enabled);
        for (JTextField field : questionInputs.values()) {
            field.setEnabled(enabled);
        }
    }

    private void setFollowUpSubmitButtonsEnabled(boolean enabled) {
        submitAnswersButton.setEnabled(enabled);
        askSuggestionButton.setEnabled(enabled);
    }

    private void setFollowUpCancelEnabled(boolean enabled) {
        cancelFollowUpButton.setEnabled(enabled);
        cancelSuggestionButton.setEnabled(enabled);
    }

    private void restoreOperatorInputs(AssessmentRequest request) {
        Map<String, String> operatorAnswers = request.getOperatorAnswers();
        for (Map.Entry<String, JTextField> entry : questionInputs.entrySet()) {
            entry.getValue().setText(operatorAnswers.getOrDefault(entry.getKey(), ""));
        }
        suggestionFollowUpArea.setText(operatorAnswers.getOrDefault(SUGGESTION_FOLLOW_UP_KEY, ""));
        if (!request.getReviewScopeExcludeClasses().isEmpty()) {
            replaceSkippedClasses(request.getReviewScopeExcludeClasses());
        } else if (!request.getReviewScopeIncludeClasses().isEmpty()) {
            List<String> excluded = new ArrayList<>(ALL_REVIEW_CLASSES);
            excluded.removeAll(request.getReviewScopeIncludeClasses());
            replaceSkippedClasses(excluded);
        } else {
            applyDefaultReviewScope();
        }
        toolHelpArea.setText(request.getToolHelpText() == null ? "" : request.getToolHelpText());
        scopeIncludesArea.setText(request.getScopeIncludesText() == null ? "" : request.getScopeIncludesText());
        scopeExcludesArea.setText(request.getScopeExcludesText() == null ? "" : request.getScopeExcludesText());
        rateLimitField.setText(request.getRateLimitText() == null ? "" : request.getRateLimitText());
        maxConcurrencyField.setText(request.getMaxConcurrencyText() == null ? "" : request.getMaxConcurrencyText());
        customHeadersArea.setText(request.getCustomHeadersText() == null ? "" : request.getCustomHeadersText());
        responseDeltaArea.setText(request.getResponseDeltaText() == null ? "" : request.getResponseDeltaText());
        programPolicyArea.setText(request.getProgramPolicyText() == null ? "" : request.getProgramPolicyText());
        burpConfigExportArea.setText(request.getBurpConfigExportText() == null ? "" : request.getBurpConfigExportText());
        burpScreenshotAuditArea.setText(request.getBurpScreenshotAuditText() == null ? "" : request.getBurpScreenshotAuditText());
        bappFindingsArea.setText(request.getBappFindingsText() == null ? "" : request.getBappFindingsText());
        loggerEvidenceArea.setText(request.getLoggerEvidenceText() == null ? "" : request.getLoggerEvidenceText());
        collaboratorEvidenceArea.setText(request.getCollaboratorEvidenceText() == null ? "" : request.getCollaboratorEvidenceText());
        toolResultsArea.setText(request.getToolResultsText() == null ? "" : request.getToolResultsText());
        evidenceTimelineEntries.clear();
        evidenceTimelineEntries.addAll(request.getEvidenceTimelineEntries());
        renderEvidenceTimeline();
        updateScopeSummary();
    }

    private DocumentListener operatorInputListener() {
        return new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                markOperatorInputCaptured();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                markOperatorInputCaptured();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                markOperatorInputCaptured();
            }
        };
    }

    private void markOperatorInputCaptured() {
        SwingUtilities.invokeLater(() -> {
            updateScopeSummary();
            if (currentAssessmentRequest != null) {
                refreshScanWorkflowText(null, currentAssessmentRequest);
            }
            if (!submitAnswersButton.isEnabled()) {
                return;
            }
            if (!hasMeaningfulOperatorContext()) {
                setFollowUpStatus(
                        "Type answers, a suggestion follow-up, or program context, then submit another AI follow-up.",
                        "Draft a suggestion-specific follow-up here, then send it to the AI when ready."
                );
            } else {
                setFollowUpStatus(
                        "Draft follow-up input captured locally. Click 'Ask AI Follow-Up' to submit it.",
                        "Draft captured locally. Click 'Ask AI Follow-Up' to send it or keep editing."
                );
            }
        });
    }

    private void addEvidenceTimelineEntry() {
        String evidenceBody = toolResultsText();
        if (evidenceBody.isBlank()) {
            setFollowUpStatus(
                    "Paste tool output or a file reference before adding it to the evidence timeline.",
                    suggestionFollowUpStatusLabel.getText()
            );
            return;
        }

        String sourceLabel = evidenceSourceField.getText().trim();
        if (sourceLabel.isBlank()) {
            sourceLabel = "manual-evidence";
        }

        String entry = "[" + timestampNow() + "] " + sourceLabel + System.lineSeparator() + evidenceBody;
        evidenceTimelineEntries.add(entry);
        renderEvidenceTimeline();
        toolResultsArea.setText("");
        evidenceSourceField.setText("");
        setFollowUpStatus(
                "Evidence entry added to the timeline. Submit a follow-up to send it to the AI.",
                suggestionFollowUpStatusLabel.getText()
        );
    }

    private void clearEvidenceTimeline() {
        evidenceTimelineEntries.clear();
        renderEvidenceTimeline();
        setFollowUpStatus(
                "Evidence timeline cleared for the current request.",
                suggestionFollowUpStatusLabel.getText()
        );
    }

    private void parseProgramRules() {
        String raw = programPolicyText();
        if (raw.isBlank()) {
            setFollowUpStatus(
                    "Paste the bug-bounty policy or scan rules into Program Notes first, then parse them.",
                    suggestionFollowUpStatusLabel.getText()
            );
            return;
        }

        ProgramRulesParser.ParsedProgramRules parsed = ProgramRulesParser.parse(raw);
        if (parsed.isEmpty()) {
            setFollowUpStatus(
                    "No structured program rules were detected. Paste more explicit lines for concurrency, headers, scope, or timing.",
                    suggestionFollowUpStatusLabel.getText()
            );
            return;
        }

        if (!parsed.maxConcurrency().isBlank()) {
            maxConcurrencyField.setText(parsed.maxConcurrency());
        }
        if (!parsed.rateLimit().isBlank()) {
            rateLimitField.setText(parsed.rateLimit());
        }
        mergeTextAreaLines(customHeadersArea, parsed.customHeaders());
        mergeTextAreaLines(scopeIncludesArea, parsed.inScopeUrls());
        mergeTextAreaLines(scopeExcludesArea, parsed.outOfScopeUrls());
        appendPolicyNotes(parsed.notes());
        markOperatorInputCaptured();

        List<String> applied = new ArrayList<>();
        if (!parsed.maxConcurrency().isBlank()) {
            applied.add("max concurrency");
        }
        if (!parsed.rateLimit().isBlank()) {
            applied.add("rate limit");
        }
        if (!parsed.customHeaders().isEmpty()) {
            applied.add(parsed.customHeaders().size() + " header(s)");
        }
        if (!parsed.inScopeUrls().isEmpty()) {
            applied.add(parsed.inScopeUrls().size() + " in-scope URL(s)");
        }
        if (!parsed.outOfScopeUrls().isEmpty()) {
            applied.add(parsed.outOfScopeUrls().size() + " out-of-scope URL(s)");
        }
        if (!parsed.notes().isEmpty()) {
            applied.add(parsed.notes().size() + " policy note(s)");
        }
        setFollowUpStatus(
                "Parsed program rules into: " + String.join(", ", applied) + ". Review the fields before launching a scan.",
                suggestionFollowUpStatusLabel.getText()
        );
    }

    private void applyBurpSettings() {
        if (burpSettingsApplier == null) {
            showBurpSettingsSyncStatus("AI Bridge Burp settings sync is not available in this build.", false);
            return;
        }
        burpSettingsApplier.run();
    }

    private void disableBurpSettings() {
        if (burpSettingsDisabler == null) {
            showBurpSettingsSyncStatus("AI Bridge Burp settings sync is not available in this build.", false);
            return;
        }
        burpSettingsDisabler.run();
    }

    private void saveAiBridgeSettings() {
        if (aiBridgeSettingsSaver == null) {
            showAiBridgeSettingsStatus("No AI-Bridge settings save handler is configured.");
            return;
        }
        showAiBridgeSettingsStatus("Saving AI-Bridge project settings...");
        aiBridgeSettingsSaver.run();
    }

    private void reloadAiBridgeSettings() {
        if (aiBridgeSettingsReloader == null) {
            showAiBridgeSettingsStatus("No AI-Bridge settings reload handler is configured.");
            return;
        }
        showAiBridgeSettingsStatus("Reloading saved AI-Bridge project settings...");
        aiBridgeSettingsReloader.run();
    }

    private void clearAiBridgeSettings() {
        if (aiBridgeSettingsClearer == null) {
            showAiBridgeSettingsStatus("No AI-Bridge settings clear handler is configured.");
            return;
        }
        showAiBridgeSettingsStatus("Clearing saved AI-Bridge project settings...");
        aiBridgeSettingsClearer.run();
    }

    private void mergeTextAreaLines(JTextArea area, List<String> values) {
        if (area == null || values == null || values.isEmpty()) {
            return;
        }
        LinkedHashMap<String, String> seen = new LinkedHashMap<>();
        for (String line : area.getText().split("\\R")) {
            String trimmed = line.trim();
            if (!trimmed.isBlank()) {
                seen.putIfAbsent(trimmed.toLowerCase(), trimmed);
            }
        }
        for (String value : values) {
            String trimmed = value == null ? "" : value.trim();
            if (!trimmed.isBlank()) {
                seen.putIfAbsent(trimmed.toLowerCase(), trimmed);
            }
        }
        area.setText(String.join(System.lineSeparator(), seen.values()));
    }

    private void appendPolicyNotes(List<String> notes) {
        if (notes == null || notes.isEmpty()) {
            return;
        }
        String existing = programPolicyArea.getText().trim();
        LinkedHashMap<String, String> seen = new LinkedHashMap<>();
        for (String line : existing.split("\\R")) {
            String trimmed = line.trim();
            if (!trimmed.isBlank()) {
                seen.putIfAbsent(trimmed.toLowerCase(), trimmed);
            }
        }
        for (String note : notes) {
            String trimmed = note == null ? "" : note.trim();
            if (!trimmed.isBlank()) {
                seen.putIfAbsent(trimmed.toLowerCase(), trimmed);
            }
        }
        programPolicyArea.setText(String.join(System.lineSeparator(), seen.values()));
    }

    private void renderEvidenceTimeline() {
        if (evidenceTimelineEntries.isEmpty()) {
            evidenceTimelineArea.setText("No evidence captured yet for this request.");
            return;
        }

        StringBuilder builder = new StringBuilder();
        for (int index = 0; index < evidenceTimelineEntries.size(); index++) {
            if (index > 0) {
                builder.append(System.lineSeparator()).append(System.lineSeparator());
            }
            builder.append(index + 1).append(". ").append(evidenceTimelineEntries.get(index));
        }
        evidenceTimelineArea.setText(builder.toString());
        evidenceTimelineArea.setCaretPosition(0);
    }

    private void resetInteractionState(boolean clearTimeline) {
        toolHelpArea.setText("");
        scopeIncludesArea.setText("");
        scopeExcludesArea.setText("");
        rateLimitField.setText("");
        maxConcurrencyField.setText("");
        customHeadersArea.setText("");
        responseDeltaArea.setText("");
        programPolicyArea.setText("");
        burpConfigExportArea.setText("");
        burpScreenshotAuditArea.setText("");
        bappFindingsArea.setText("");
        loggerEvidenceArea.setText("");
        collaboratorEvidenceArea.setText("");
        toolResultsArea.setText("");
        suggestionFollowUpArea.setText("");
        evidenceSourceField.setText("");
        if (clearTimeline) {
            evidenceTimelineEntries.clear();
            renderEvidenceTimeline();
        }
    }

    private boolean hasMeaningfulOperatorContext() {
        return !currentAnswers().isEmpty()
                || !reviewScopeIncludeClasses().equals(List.copyOf(ALL_REVIEW_CLASSES))
                || !toolHelpText().isBlank()
                || !scopeIncludesText().isBlank()
                || !scopeExcludesText().isBlank()
                || !rateLimitText().isBlank()
                || !maxConcurrencyText().isBlank()
                || !customHeadersText().isBlank()
                || !responseDeltaText().isBlank()
                || !programPolicyText().isBlank()
                || !burpConfigExportText().isBlank()
                || !burpScreenshotAuditText().isBlank()
                || !savedBurpToolsText().isBlank()
                || !bappFindingsText().isBlank()
                || !loggerEvidenceText().isBlank()
                || !collaboratorEvidenceText().isBlank()
                || !toolResultsText().isBlank()
                || !suggestionFollowUpText().isBlank()
                || !evidenceTimelineEntries.isEmpty();
    }

    private void setFollowUpStatus(String operatorStatus, String suggestionStatus) {
        operatorInputStatusLabel.setText(operatorStatus);
        suggestionFollowUpStatusLabel.setText(suggestionStatus);
    }

    private void addSkippedClass() {
        Object value = skipClassCombo.getSelectedItem();
        if (value == null) {
            return;
        }
        String vulnClass = value.toString();
        if (!reviewScopeExcludeClasses().contains(vulnClass)) {
            skippedScopeModel.addElement(vulnClass);
        }
        updateScopeSummary();
        markOperatorInputCaptured();
    }

    private void removeSelectedSkippedClasses() {
        List<String> selected = skippedScopeList.getSelectedValuesList();
        if (selected.isEmpty()) {
            return;
        }
        for (String value : selected) {
            skippedScopeModel.removeElement(value);
        }
        updateScopeSummary();
        markOperatorInputCaptured();
    }

    private void replaceSkippedClasses(List<String> values) {
        skippedScopeModel.clear();
        for (String value : values) {
            String normalized = value == null ? "" : value.trim().toLowerCase();
            if (!normalized.isBlank() && ALL_REVIEW_CLASSES.contains(normalized) && !reviewScopeExcludeClasses().contains(normalized)) {
                skippedScopeModel.addElement(normalized);
            }
        }
    }

    private void applyDefaultReviewScope() {
        replaceSkippedClasses(List.of());
        updateScopeSummary();
    }

    private void updateScopeSummary() {
        activeProfileField.setText(DEFAULT_RUNTIME_STRATEGY);
        activeProfileField.setCaretPosition(0);

        List<String> selectedClasses = reviewScopeIncludeClasses();
        List<String> skippedClasses = reviewScopeExcludeClasses();
        String summary;
        if (selectedClasses.isEmpty()) {
            summary = "No classes selected";
        } else if (skippedClasses.isEmpty()) {
            summary = "Skipping none (" + selectedClasses.size() + " active)";
        } else if (skippedClasses.size() <= 4) {
            summary = "Skip: " + String.join(", ", skippedClasses);
        } else {
            summary = "Skip: " + String.join(", ", skippedClasses.subList(0, 4)) + " +" + (skippedClasses.size() - 4) + " more";
        }

        scanScopeSummaryField.setText(summary);
        scanScopeSummaryField.setToolTipText(
                skippedClasses.isEmpty()
                        ? "No vulnerability classes are skipped for this request."
                        : "Skipped classes: " + String.join(", ", skippedClasses)
        );
        scanScopeSummaryField.setCaretPosition(0);
    }

    private void updateReportLinks(String jobId) {
        if (jobId == null || jobId.isBlank()) {
            reportJsonField.setText("Awaiting completed job");
            reportMarkdownField.setText("Awaiting completed job");
            return;
        }
        String endpoint = endpointUrl();
        String base = endpoint.endsWith("/api/analyze")
                ? endpoint.substring(0, endpoint.length() - "/api/analyze".length())
                : endpoint;
        reportJsonField.setText(base + "/api/history/jobs/" + jobId);
        reportMarkdownField.setText(base + "/api/history/jobs/" + jobId + "/report.md");
        reportJsonField.setCaretPosition(0);
        reportMarkdownField.setCaretPosition(0);
    }

    private String formatBulletList(List<String> items, String emptyMessage) {
        if (items == null || items.isEmpty()) {
            return emptyMessage;
        }

        StringBuilder builder = new StringBuilder();
        for (String item : items) {
            if (builder.length() > 0) {
                builder.append(System.lineSeparator()).append(System.lineSeparator());
            }
            builder.append("- ").append(item);
        }
        return builder.toString();
    }

    private String formatSourceLinks(List<String> links) {
        if (links == null || links.isEmpty()) {
            return "No source links were returned for this advisory response.";
        }
        return String.join(System.lineSeparator(), links);
    }

    private String formatReasoningSummary(AnalysisReasoningResponse reasoning) {
        if (reasoning == null) {
            return "No stored reasoning summary is available yet.";
        }

        Map<String, Object> topHypothesis = reasoning.getTopHypothesis();
        StringBuilder builder = new StringBuilder();
        builder.append("Job: ").append(reasoning.getJobId()).append(System.lineSeparator());
        builder.append("Target: ").append(reasoning.getTargetUrl()).append(System.lineSeparator());
        builder.append(System.lineSeparator()).append("Top hypothesis:").append(System.lineSeparator());
        if (topHypothesis.isEmpty()) {
            builder.append("- None stored yet.");
        } else {
            builder.append("- Class: ").append(String.valueOf(topHypothesis.getOrDefault("vuln_class", ""))).append(System.lineSeparator());
            builder.append("- Summary: ").append(String.valueOf(topHypothesis.getOrDefault("summary", ""))).append(System.lineSeparator());
            builder.append("- Status: ").append(String.valueOf(topHypothesis.getOrDefault("status", ""))).append(System.lineSeparator());
            builder.append("- Confidence: ").append(String.valueOf(topHypothesis.getOrDefault("confidence", "")));
        }

        appendReasoningSection(builder, "Phase highlights", reasoning.getPhaseHighlights());
        appendStringSection(builder, "Confidence drivers", reasoning.getConfidenceDrivers(), "No confidence drivers were stored.");
        appendReasoningEvidenceSection(builder, "Key evidence", reasoning.getKeyEvidence());
        appendStringSection(builder, "Downgrade reasons", reasoning.getDowngradeReasons(), "No downgrade reasons were stored.");

        Map<String, Object> nextDecision = reasoning.getNextDecision();
        builder.append(System.lineSeparator()).append(System.lineSeparator()).append("Next decision:").append(System.lineSeparator());
        if (nextDecision.isEmpty()) {
            builder.append("- No next decision was stored.");
        } else {
            for (Map.Entry<String, Object> entry : nextDecision.entrySet()) {
                builder.append("- ").append(entry.getKey()).append(": ").append(String.valueOf(entry.getValue())).append(System.lineSeparator());
            }
        }
        return builder.toString().trim();
    }

    private String formatPhaseHistory(PhaseHistoryResponse phaseHistory) {
        if (phaseHistory == null || phaseHistory.getItems().isEmpty()) {
            return "No phase history snapshots are available yet.";
        }

        StringBuilder builder = new StringBuilder();
        builder.append("Job: ").append(phaseHistory.getJobId()).append(System.lineSeparator());
        builder.append("Snapshots: ").append(phaseHistory.getCount()).append(System.lineSeparator());
        for (PhaseSnapshotResponse item : phaseHistory.getItems()) {
            builder.append(System.lineSeparator())
                    .append("[").append(item.getPhase()).append("] ")
                    .append(item.getCreatedAt()).append(System.lineSeparator())
                    .append(String.valueOf(item.getResult()));
        }
        return builder.toString().trim();
    }

    private void appendReasoningSection(StringBuilder builder, String title, List<AnalysisReasoningPhaseResponse> items) {
        builder.append(System.lineSeparator()).append(System.lineSeparator()).append(title).append(":").append(System.lineSeparator());
        if (items == null || items.isEmpty()) {
            builder.append("- None");
            return;
        }
        for (AnalysisReasoningPhaseResponse item : items) {
            builder.append("- ").append(item.getPhase()).append(": ").append(item.getSummary()).append(System.lineSeparator());
        }
    }

    private void appendReasoningEvidenceSection(StringBuilder builder, String title, List<AnalysisReasoningEvidenceResponse> items) {
        builder.append(System.lineSeparator()).append(System.lineSeparator()).append(title).append(":").append(System.lineSeparator());
        if (items == null || items.isEmpty()) {
            builder.append("- None");
            return;
        }
        for (AnalysisReasoningEvidenceResponse item : items) {
            builder.append("- ")
                    .append(item.getEvidenceType().isBlank() ? item.getSource() : item.getEvidenceType())
                    .append(": ")
                    .append(item.getSummary())
                    .append(" (confidence=")
                    .append(item.getConfidence())
                    .append(")")
                    .append(System.lineSeparator());
        }
    }

    private void appendStringSection(StringBuilder builder, String title, List<String> items, String emptyMessage) {
        builder.append(System.lineSeparator()).append(System.lineSeparator()).append(title).append(":").append(System.lineSeparator());
        if (items == null || items.isEmpty()) {
            builder.append("- ").append(emptyMessage);
            return;
        }
        for (String item : items) {
            builder.append("- ").append(item).append(System.lineSeparator());
        }
    }

    private String pendingScanBridgeGuidance(AssessmentRequest request) {
        if (request == null) {
            return "Analyze selected Burp issues or recent scan findings to get confirmation guidance here.";
        }
        String sourceLabel = requestOriginLabel(request);
        if (isScannerFindingRequest(request)) {
            return "AI Bridge is turning the selected " + sourceLabel.toLowerCase() + " into a confirmation plan. "
                    + "When the job completes, this panel will show the next Burp action, matching BChecks, "
                    + "concrete Repeater or Intruder validation steps, and the best impact-oriented reporting path.";
        }
        return "AI Bridge is preparing local guidance for the current " + sourceLabel.toLowerCase()
                + ". This panel will show the next tool, payload family, validation order, and reporting evidence path when the job completes.";
    }

    private String buildScanBridgeGuidance(AdvisoryResponse response, AssessmentRequest request) {
        if (response == null) {
            return pendingScanBridgeGuidance(request);
        }

        StringBuilder builder = new StringBuilder();
        builder.append("Source: ").append(requestOriginLabel(request)).append(System.lineSeparator());
        if (isScannerFindingRequest(request)) {
            builder.append("Confirmation plan based on selected Burp findings:");
        } else {
            builder.append("Current advisory guidance for Burp confirmation:");
        }

        builder.append(System.lineSeparator())
                .append("- Primary next action: ")
                .append(response.getPrimaryNextAction());

        appendScanGuidanceSection(builder, "Immediate validation steps", response.getRequestPlan(), 3);
        appendScanGuidanceSection(builder, "Suggested BChecks to enable or compare", response.getBcheckRecommendations(), 3);
        appendScanGuidanceSection(builder, "Burp settings to review", response.getBurpSettingsRecommendations(), 3);
        appendScanGuidanceSection(builder, "Burp or external tooling to use next", response.getManualTooling(), 3);
        appendScanGuidanceSection(builder, "Concrete commands or attack steps", response.getManualCommands(), 3);
        appendScanGuidanceSection(builder, "Suggested payload lists", response.getPayloadRecommendations(), 2);
        appendScanGuidanceSection(builder, "Impact paths to validate after confirmation", response.getImpactPaths(), 2);
        appendScanGuidanceSection(builder, "Confirmation playbooks", response.getConfirmationPlaybooks(), 2);

        builder.append(System.lineSeparator()).append(System.lineSeparator())
                .append("Note: AI Bridge can recommend matching BChecks, Repeater edits, Intruder payloads, and validation workflow, "
                        + "but Montoya does not expose Burp's saved scan configuration wizard, per-scan custom BCheck toggles, "
                        + "or automatic payload injection into Burp Scanner. Payload lists here are for Repeater or Intruder follow-up.");
        return builder.toString();
    }

    private void refreshScanWorkflowText(AdvisoryResponse response, AssessmentRequest request) {
        latestDetailedWorkflowText = buildDetailedNewScanHandoff(response, request);
        newScanHandoffArea.setText(buildNewScanHandoff(response, request));
        newScanHandoffArea.setCaretPosition(0);
    }

    private String buildNewScanHandoff(AdvisoryResponse response, AssessmentRequest request) {
        String targetUrl = request == null || request.getTargetUrl() == null ? "" : request.getTargetUrl().trim();
        String sourceLabel = requestOriginLabel(request);
        String selectedScanType = String.valueOf(scanTypeCombo.getSelectedItem());
        String selectedAuditConfig = String.valueOf(auditConfigurationCombo.getSelectedItem());
        List<String> listedBchecks = allScanBcheckEntries();

        StringBuilder builder = new StringBuilder();
        builder.append("Source: ").append(sourceLabel).append(System.lineSeparator());
        builder.append("Target: ").append(targetUrl.isBlank() ? "<set target first>" : targetUrl).append(System.lineSeparator());
        builder.append("Scan mode: ").append(selectedScanType).append(" | ").append(selectedAuditConfig).append(System.lineSeparator());

        if (response != null) {
            builder.append(System.lineSeparator()).append("What to do first:").append(System.lineSeparator());
            builder.append("1. ").append(response.getPrimaryNextAction()).append(System.lineSeparator());
            appendIndentedSection(builder, "2. Readiness and setup", response.getProjectReadinessChecks(), 3);
            appendIndentedSection(builder, "3. Burp actions", response.getBurpActionChecklist(), 4);
            appendIndentedSection(builder, "4. BChecks to review", listedBchecks.isEmpty() ? response.getBcheckRecommendations() : listedBchecks, 3);
            appendIndentedSection(builder, "5. Impact path after confirmation", response.getImpactPaths(), 2);
        } else {
            builder.append(System.lineSeparator())
                    .append("AI Bridge is preparing a short Burp workflow for this request. ")
                    .append("Use the buttons above to review findings or run a focused scan when ready.");
        }

        if (!customHeadersText().isBlank()) {
            builder.append(System.lineSeparator()).append(System.lineSeparator())
                    .append("Required headers are already captured in Program Context. Keep them applied before scanning.");
        }
        return builder.toString().trim();
    }

    private String buildDetailedNewScanHandoff(AdvisoryResponse response, AssessmentRequest request) {
        String targetUrl = request == null ? "" : (request.getTargetUrl() == null ? "" : request.getTargetUrl().trim());
        String sourceLabel = requestOriginLabel(request);
        String selectedScanType = String.valueOf(scanTypeCombo.getSelectedItem());
        String selectedAuditConfig = String.valueOf(auditConfigurationCombo.getSelectedItem());
        List<String> listedBchecks = allScanBcheckEntries();

        StringBuilder builder = new StringBuilder();
        builder.append("Use this phased Burp workflow to move from confirmation to reportable impact. ")
                .append("AI Bridge cannot open or populate Burp's native New Scan wizard through Montoya, so this is a precise operator handoff.")
                .append(System.lineSeparator()).append(System.lineSeparator());

        builder.append("Source: ").append(sourceLabel).append(System.lineSeparator());
        builder.append("Target URL: ").append(targetUrl.isBlank() ? "<set target first>" : targetUrl).append(System.lineSeparator());
        builder.append("Recommended scan type: ").append(selectedScanType).append(System.lineSeparator());
        builder.append("Recommended audit configuration: ").append(selectedAuditConfig).append(System.lineSeparator());

        builder.append(System.lineSeparator()).append("Phase -1 - Project readiness gate:").append(System.lineSeparator());
        if (response != null) {
            builder.append("- ").append(response.getProjectReadinessSummary()).append(System.lineSeparator());
            appendIndentedSection(builder, "- Readiness blockers and checks", response.getProjectReadinessChecks(), 6);
        } else {
            builder.append("- Waiting for AI Bridge to score project readiness for this request.").append(System.lineSeparator());
        }

        builder.append(System.lineSeparator()).append("Phase 0 - Burp settings and project preparation:").append(System.lineSeparator());
        if (response != null && !response.getBurpSettingsRecommendations().isEmpty()) {
            appendIndentedSection(builder, "- Burp settings to review before testing", response.getBurpSettingsRecommendations(), 6);
        } else {
            builder.append("- Review project scope, session handling, logging, and any required proxy-level header handling before broader testing.")
                    .append(System.lineSeparator());
        }

        builder.append(System.lineSeparator()).append("Phase 1 - Burp New Scan handoff:").append(System.lineSeparator());
        builder.append("1. Scan type: choose ").append(selectedScanType).append(".").append(System.lineSeparator());
        builder.append("2. Scan details > URLs to scan: add ").append(targetUrl.isBlank() ? "the selected target URL" : targetUrl).append(".").append(System.lineSeparator());
        builder.append("3. Scan configuration > Audit behaviour: use ").append(selectedAuditConfig).append(" as the closest Burp setting.").append(System.lineSeparator());

        String concurrency = maxConcurrencyText();
        String rateLimit = rateLimitText();
        if (!concurrency.isBlank() || !rateLimit.isBlank()) {
            builder.append("4. Resource pool: ");
            if (!concurrency.isBlank()) {
                builder.append("set maximum concurrent requests to ").append(concurrency).append(". ");
            }
            if (!rateLimit.isBlank()) {
                builder.append("apply request pacing or delay that matches: ").append(rateLimit).append(". ");
            }
            builder.append("If the bug-bounty program requires a lower limit, create or select a dedicated pool in Burp's Resource pool step.")
                    .append(System.lineSeparator());
        } else {
            builder.append("4. Resource pool: choose or create a pool that matches the program's concurrency and delay rules before scanning.")
                    .append(System.lineSeparator());
        }

        if (!customHeadersText().isBlank()) {
            builder.append("5. Required headers or request context:").append(System.lineSeparator());
            for (String line : customHeadersText().split("\\R")) {
                String trimmed = line.trim();
                if (!trimmed.isBlank()) {
                    builder.append("   - ").append(trimmed).append(System.lineSeparator());
                }
            }
            builder.append("   Apply these in the relevant Burp authentication, session, or upstream request handling flow before launching the scan.")
                    .append(System.lineSeparator());
        } else {
            builder.append("5. Required headers or request context: no custom headers are currently captured in AI Bridge.").append(System.lineSeparator());
        }

        if (!listedBchecks.isEmpty()) {
            builder.append("6. BChecks to verify before scanning:").append(System.lineSeparator());
            for (String item : listedBchecks) {
                builder.append("   - ").append(item).append(System.lineSeparator());
            }
            builder.append("   AI Bridge can import these globally, but you still need to verify the matching checks are enabled in Burp's scan configuration.")
                    .append(System.lineSeparator());
        } else {
            builder.append("6. BChecks to verify before scanning: none are listed yet. Analyze the selected issue first or add entries from the catalog.")
                    .append(System.lineSeparator());
        }

        if (!scopeIncludesText().isBlank() || !scopeExcludesText().isBlank()) {
            builder.append("7. Scope notes:").append(System.lineSeparator());
            if (!scopeIncludesText().isBlank()) {
                builder.append("   - In scope: ").append(compactSingleLine(scopeIncludesText(), 240)).append(System.lineSeparator());
            }
            if (!scopeExcludesText().isBlank()) {
                builder.append("   - Out of scope: ").append(compactSingleLine(scopeExcludesText(), 240)).append(System.lineSeparator());
            }
        } else {
            builder.append("7. Scope notes: use the target URL and the program rules currently in scope.").append(System.lineSeparator());
        }

        if (!programPolicyText().isBlank()) {
            builder.append("8. Program policy notes: ").append(compactSingleLine(programPolicyText(), 280)).append(System.lineSeparator());
        }

        builder.append(System.lineSeparator()).append("Phase 2 - Burp Repeater confirmation:").append(System.lineSeparator());
        if (response != null) {
            builder.append("- Primary next action: ").append(response.getPrimaryNextAction()).append(System.lineSeparator());
            appendIndentedSection(builder, "- Burp action checklist", response.getBurpActionChecklist(), 6);
            appendIndentedSection(builder, "- First Burp-side validation steps", response.getRequestPlan(), 4);
            appendRepeaterTrack(builder, response);
            builder.append(System.lineSeparator()).append("Phase 3 - Burp Intruder expansion:").append(System.lineSeparator());
            appendIntruderTrack(builder, response);
            builder.append(System.lineSeparator()).append("Phase 4 - Impact validation for bug bounty:").append(System.lineSeparator());
            appendImpactTrack(builder, response);
            builder.append(System.lineSeparator()).append("Phase 5 - Reporting evidence to collect:").append(System.lineSeparator());
            appendReportingTrack(builder, response, request);
        } else {
            builder.append("- Waiting for AI Bridge to finish the issue-specific handoff.").append(System.lineSeparator());
            builder.append(System.lineSeparator()).append("Phase 3 - Burp Intruder expansion:").append(System.lineSeparator());
            builder.append("- Pending issue-specific guidance.").append(System.lineSeparator());
            builder.append(System.lineSeparator()).append("Phase 4 - Impact validation for bug bounty:").append(System.lineSeparator());
            builder.append("- Pending issue-specific guidance.").append(System.lineSeparator());
            builder.append(System.lineSeparator()).append("Phase 5 - Reporting evidence to collect:").append(System.lineSeparator());
            builder.append("- Pending issue-specific guidance.").append(System.lineSeparator());
        }

        builder.append(System.lineSeparator())
                .append("Note: payload lists and manual commands are follow-up guidance for Repeater or Intruder. ")
                .append("Burp Scanner's native New Scan wizard does not accept arbitrary AI-generated payload lists from extensions.");
        return builder.toString().trim();
    }

    private void appendRepeaterTrack(StringBuilder builder, AdvisoryResponse response) {
        List<String> payloads = response.getPayloadRecommendations();
        List<String> playbooks = response.getConfirmationPlaybooks();
        if (!payloads.isEmpty()) {
            builder.append("- Use Repeater first with one baseline tab and one delta at a time.").append(System.lineSeparator());
            appendIndentedSection(builder, "- Starter payloads for the first few Repeater tabs", payloads, 3);
        }
        if (!playbooks.isEmpty()) {
            appendIndentedSection(builder, "- Confirmation playbooks to follow while in Repeater", playbooks, 2);
        }
        if (payloads.isEmpty() && playbooks.isEmpty()) {
            builder.append("- Build a baseline tab, duplicate it, change one parameter or structure at a time, and record the response delta after each send.")
                    .append(System.lineSeparator());
        }
    }

    private void appendIntruderTrack(StringBuilder builder, AdvisoryResponse response) {
        List<String> queue = response.getSuggestionQueue();
        List<String> payloads = response.getPayloadRecommendations();
        boolean added = false;
        for (String item : queue) {
            if (item == null) {
                continue;
            }
            String lowered = item.toLowerCase();
            if (lowered.contains("intruder")) {
                builder.append("- ").append(item).append(System.lineSeparator());
                added = true;
            }
        }
        if (!payloads.isEmpty()) {
            builder.append("- If Repeater confirms the signal, move only the proven parameter or XML/body segment into Intruder with a very short custom list first.")
                    .append(System.lineSeparator());
            added = true;
        }
        if (!added) {
            builder.append("- Use Intruder only after Repeater identifies a promising field. Keep the attack narrow, use the smallest custom payload set first, and compare response deltas rather than volume.")
                    .append(System.lineSeparator());
        }
    }

    private void appendImpactTrack(StringBuilder builder, AdvisoryResponse response) {
        List<String> impactPaths = response.getImpactPaths();
        List<String> confidence = response.getConfidenceByClass();
        if (!impactPaths.isEmpty()) {
            builder.append("- Highest-value impact branches to test next:").append(System.lineSeparator());
            int count = 0;
            for (String path : impactPaths) {
                if (path == null || path.isBlank()) {
                    continue;
                }
                builder.append("  - ").append(path).append(System.lineSeparator());
                count++;
                if (count >= 3) {
                    break;
                }
            }
        } else {
            builder.append("- If the issue only shows weak parser or validation differences with no unauthorized data, state change, or trust-boundary break, treat it as low-impact until stronger evidence appears.")
                    .append(System.lineSeparator());
        }
        if (!confidence.isEmpty()) {
            appendIndentedSection(builder, "- Confidence notes to justify or de-prioritize escalation", confidence, 2);
        }
    }

    private void appendReportingTrack(StringBuilder builder, AdvisoryResponse response, AssessmentRequest request) {
        builder.append("- Capture the original baseline request and response for ").append(requestOriginLabel(request)).append(".").append(System.lineSeparator());
        builder.append("- Capture the changed request and the exact response delta that proves the behavior changed.").append(System.lineSeparator());
        builder.append("- Record which parameter, header, cookie, body node, or insertion point caused the difference.").append(System.lineSeparator());
        builder.append("- Record whether the impact is unauthorized data access, privilege expansion, server-side fetch behavior, state change, or sensitive disclosure.").append(System.lineSeparator());
        List<String> playbooks = response.getConfirmationPlaybooks();
        if (!playbooks.isEmpty()) {
            appendIndentedSection(builder, "- Extra evidence expectations from the matched playbooks", playbooks, 2);
        }
        List<String> history = response.getHistoryCorrelation();
        if (!history.isEmpty()) {
            appendIndentedSection(builder, "- History or correlation notes worth citing in a report", history, 2);
        }
    }

    private void appendIndentedSection(StringBuilder builder, String title, List<String> items, int maxItems) {
        if (items == null || items.isEmpty() || maxItems <= 0) {
            return;
        }
        builder.append(title).append(":").append(System.lineSeparator());
        int count = 0;
        for (String item : items) {
            if (item == null || item.isBlank()) {
                continue;
            }
            builder.append("  - ").append(item).append(System.lineSeparator());
            count++;
            if (count >= maxItems) {
                break;
            }
        }
    }

    private List<String> allScanBcheckEntries() {
        List<String> entries = new ArrayList<>();
        for (int index = 0; index < scanLaunchBcheckModel.size(); index++) {
            String value = scanLaunchBcheckModel.getElementAt(index);
            if (value != null && !value.isBlank()) {
                entries.add(value);
            }
        }
        return entries;
    }

    private void appendScanGuidanceSection(StringBuilder builder, String title, List<String> items, int maxItems) {
        if (items == null || items.isEmpty() || maxItems <= 0) {
            return;
        }

        builder.append(System.lineSeparator()).append(System.lineSeparator()).append(title).append(":");
        int count = 0;
        for (String item : items) {
            if (item == null || item.isBlank()) {
                continue;
            }
            builder.append(System.lineSeparator()).append("- ").append(item);
            count++;
            if (count >= maxItems) {
                break;
            }
        }
    }

    private boolean isScannerFindingRequest(AssessmentRequest request) {
        if (request == null) {
            return false;
        }
        String sourceTool = request.getSourceTool() == null ? "" : request.getSourceTool().toLowerCase();
        if (sourceTool.contains("audit-issue")) {
            return true;
        }
        return request.getAnnotations().contains("audit_issue_selected")
                || request.getAnnotations().contains("scanner_auto_triage");
    }

    private String requestOriginLabel(AssessmentRequest request) {
        if (request == null) {
            return "Request";
        }
        String sourceTool = request.getSourceTool() == null ? "" : request.getSourceTool().toLowerCase();
        if (request.getAnnotations().contains("audit_issue_selected") || sourceTool.contains("audit-issue")) {
            if (sourceTool.contains("scanner")) {
                return "Scanner Audit Issue";
            }
            return "Audit Issue";
        }
        if (sourceTool.contains("repeater")) {
            return "Repeater Request";
        }
        if (sourceTool.contains("intruder")) {
            return "Intruder Request";
        }
        if (sourceTool.contains("scanner")) {
            return "Scanner Request";
        }
        if (sourceTool.contains("proxy")) {
            return "Proxy Request";
        }
        return "Request";
    }

    private String requestMethodLabel(AssessmentRequest request) {
        if (request == null) {
            return "-";
        }
        String method = request.getHttpMethod() == null || request.getHttpMethod().isBlank()
                ? "-"
                : request.getHttpMethod();
        return method + " via " + requestOriginLabel(request);
    }

    private void selectResultsTab(String title) {
        int tabIndex = findTabIndex(resultsTabs, title);
        if (tabIndex >= 0) {
            resultsTabs.setSelectedIndex(tabIndex);
        }
    }

    private int findTabIndex(JTabbedPane tabbedPane, String title) {
        if (tabbedPane == null || title == null || title.isBlank()) {
            return -1;
        }
        for (int index = 0; index < tabbedPane.getTabCount(); index++) {
            if (title.equals(tabbedPane.getTitleAt(index))) {
                return index;
            }
        }
        return -1;
    }

    private void selectBestResultTab(AdvisoryResponse response, AssessmentRequest request, boolean hadFollowUpContext) {
        if (response == null) {
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
            return;
        }
        String source = request == null || request.getSourceTool() == null ? "" : request.getSourceTool().toLowerCase();
        if (source.contains("repeater")) {
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
            return;
        }
        if (source.contains("intruder")) {
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
            return;
        }
        if (!response.getRequestPlan().isEmpty()) {
            selectResultsTab(RESULTS_TAB_REQUEST_PLAN);
            return;
        }
        if (!response.getManualCommands().isEmpty()) {
            selectResultsTab(RESULTS_TAB_TOOLING);
            return;
        }
        if (!hadFollowUpContext && !response.getSuggestionQueue().isEmpty()) {
            workspaceTabs.setSelectedIndex(Math.min(WORKSPACE_TAB_SUGGESTIONS, workspaceTabs.getTabCount() - 1));
            return;
        }
        selectResultsTab(RESULTS_TAB_AI_ANALYSIS);
    }

    private String indentBlock(String text, String prefix) {
        StringBuilder builder = new StringBuilder();
        String[] lines = text.split("\\R");
        for (int index = 0; index < lines.length; index++) {
            if (index > 0) {
                builder.append(System.lineSeparator());
            }
            builder.append(prefix).append(lines[index]);
        }
        return builder.toString();
    }

    private String joinTextBlocks(String first, String second) {
        String left = first == null ? "" : first.trim();
        String right = second == null ? "" : second.trim();
        if (left.isBlank()) {
            return right;
        }
        if (right.isBlank()) {
            return left;
        }
        return left + System.lineSeparator() + System.lineSeparator() + right;
    }

    private String joinLabeledTextBlocks(String firstLabel, String first, String secondLabel, String second) {
        List<String> blocks = new ArrayList<>();
        String firstValue = first == null ? "" : first.trim();
        if (!firstValue.isBlank()) {
            blocks.add(firstLabel + ":" + System.lineSeparator() + firstValue);
        }
        String secondValue = second == null ? "" : second.trim();
        if (!secondValue.isBlank()) {
            blocks.add(secondLabel + ":" + System.lineSeparator() + secondValue);
        }
        return String.join(System.lineSeparator() + System.lineSeparator(), blocks);
    }

    private String timestampNow() {
        return LocalDateTime.now().format(TIMESTAMP_FORMAT);
    }

    private record InvestigationTranscriptEntry(String timestamp, String speakerLabel, String message) {
    }

    public static final class InvestigationTranscriptState {
        public String timestamp;
        public String speaker;
        public String message;
    }

    private record InvestigationNotebookEntry(String timestamp, String kind, String title, String details) {
    }

    public static final class InvestigationNotebookEntryState {
        public String timestamp;
        public String kind;
        public String title;
        public String details;
    }

    private boolean requestHasFollowUpContext(AssessmentRequest request) {
        return !request.getOperatorAnswers().isEmpty()
                || !request.getReviewScopeIncludeClasses().equals(List.copyOf(ALL_REVIEW_CLASSES))
                || (request.getToolHelpText() != null && !request.getToolHelpText().isBlank())
                || (request.getScopeIncludesText() != null && !request.getScopeIncludesText().isBlank())
                || (request.getScopeExcludesText() != null && !request.getScopeExcludesText().isBlank())
                || (request.getRateLimitText() != null && !request.getRateLimitText().isBlank())
                || (request.getMaxConcurrencyText() != null && !request.getMaxConcurrencyText().isBlank())
                || (request.getCustomHeadersText() != null && !request.getCustomHeadersText().isBlank())
                || (request.getResponseDeltaText() != null && !request.getResponseDeltaText().isBlank())
                || (request.getProgramPolicyText() != null && !request.getProgramPolicyText().isBlank())
                || (request.getBappFindingsText() != null && !request.getBappFindingsText().isBlank())
                || (request.getCollaboratorEvidenceText() != null && !request.getCollaboratorEvidenceText().isBlank())
                || (request.getToolResultsText() != null && !request.getToolResultsText().isBlank())
                || !request.getIssueWorkflowNotes().isEmpty()
                || (request.getInvestigationNotebookText() != null && !request.getInvestigationNotebookText().isBlank())
                || !request.getEvidenceTimelineEntries().isEmpty();
    }
}
