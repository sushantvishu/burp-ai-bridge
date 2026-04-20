package server.samples.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.ITab;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.io.BufferedReader;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/*
 * Burp AI Bridge companion panel sketch for Burp Suite Pro.
 * This is a starter template that shows the panel actions and HTTP calls.
 */
public class BurpAiBridgePanel implements IBurpExtender, ITab, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private JPanel panel;
    private JTextArea output;
    private JTextArea requestView;
    private JTextArea responseView;
    private JTextField baseUrlField;
    private JTextField issueField;
    private JTextField snapshotField;
    private JTextField currentModelField;
    private JTextField switchModelField;
    private IHttpRequestResponse[] selectedMessages = new IHttpRequestResponse[0];
    private String baseUrl = "http://127.0.0.1:8000";
    private String currentIssueId = "";
    private String currentSnapshotId = "";
    private String currentTargetUrl = "";
    private String currentModel = "";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("Burp AI Bridge Companion");
        callbacks.registerContextMenuFactory(this);

        panel = new JPanel(new BorderLayout());
        output = new JTextArea(24, 100);
        output.setEditable(false);
        output.setLineWrap(false);
        output.setWrapStyleWord(false);
        output.setFont(new Font("Consolas", Font.PLAIN, 12));
        requestView = new JTextArea(18, 100);
        requestView.setEditable(false);
        requestView.setLineWrap(false);
        requestView.setWrapStyleWord(false);
        requestView.setFont(new Font("Consolas", Font.PLAIN, 12));
        responseView = new JTextArea(18, 100);
        responseView.setEditable(false);
        responseView.setLineWrap(false);
        responseView.setWrapStyleWord(false);
        responseView.setFont(new Font("Consolas", Font.PLAIN, 12));

        JPanel controls = new JPanel(new GridLayout(2, 1));
        JPanel toolbar = new JPanel();
        JPanel info = new JPanel();
        baseUrlField = new JTextField(baseUrl, 28);
        issueField = new JTextField("", 18);
        snapshotField = new JTextField("", 18);
        currentModelField = new JTextField("", 18);
        switchModelField = new JTextField("", 18);
        issueField.setEditable(false);
        snapshotField.setEditable(false);
        currentModelField.setEditable(false);
        JButton openPlan = new JButton("Open Plan in Repeater");
        JButton syncTabs = new JButton("Sync Selected Tabs");
        JButton refresh = new JButton("Refresh Panel State");
        JButton recommendMoves = new JButton("Show Burp Moves");
        JButton refreshModels = new JButton("Refresh Model Options");
        JButton switchModel = new JButton("Switch Active Model");
        JButton resetModel = new JButton("Reset Model");

        openPlan.addActionListener(event -> openPlanInRepeater());
        syncTabs.addActionListener(event -> syncSelectedTabs());
        refresh.addActionListener(event -> refreshPanelState());
        recommendMoves.addActionListener(event -> showBurpMoves());
        refreshModels.addActionListener(event -> refreshModelOptions());
        switchModel.addActionListener(event -> switchActiveModel());
        resetModel.addActionListener(event -> resetActiveModel());

        toolbar.add(new JLabel("Bridge URL"));
        toolbar.add(baseUrlField);
        toolbar.add(openPlan);
        toolbar.add(syncTabs);
        toolbar.add(refresh);
        toolbar.add(recommendMoves);
        toolbar.add(refreshModels);
        info.add(new JLabel("Issue"));
        info.add(issueField);
        info.add(new JLabel("Snapshot"));
        info.add(snapshotField);
        info.add(new JLabel("Model"));
        info.add(currentModelField);
        info.add(new JLabel("Switch To"));
        info.add(switchModelField);
        info.add(switchModel);
        info.add(resetModel);

        controls.add(toolbar);
        controls.add(info);

        panel.add(controls, BorderLayout.NORTH);
        JScrollPane outputScroll = new JScrollPane(output);
        outputScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        JScrollPane requestScroll = new JScrollPane(requestView);
        requestScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        JScrollPane responseScroll = new JScrollPane(responseView);
        responseScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Bridge Output", outputScroll);
        tabs.addTab("Selected Request", requestScroll);
        tabs.addTab("Selected Response", responseScroll);
        panel.add(tabs, BorderLayout.CENTER);

        callbacks.addSuiteTab(this);
        append("Burp AI Bridge companion loaded.\n");
    }

    @Override
    public String getTabCaption() {
        return "AI Bridge";
    }

    @Override
    public java.awt.Component getUiComponent() {
        return panel;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        selectedMessages = invocation.getSelectedMessages() != null ? invocation.getSelectedMessages() : new IHttpRequestResponse[0];
        List<JMenuItem> items = new ArrayList<>();
        JMenuItem openItem = new JMenuItem("AI Bridge: Open plan in Repeater");
        JMenuItem syncItem = new JMenuItem("AI Bridge: Sync selected tabs");
        JMenuItem refreshItem = new JMenuItem("AI Bridge: Refresh panel state");
        JMenuItem recommendItem = new JMenuItem("AI Bridge: Show Burp moves");
        openItem.addActionListener(event -> openPlanInRepeater());
        syncItem.addActionListener(event -> syncSelectedTabs());
        refreshItem.addActionListener(event -> refreshPanelState());
        recommendItem.addActionListener(event -> showBurpMoves());
        items.add(openItem);
        items.add(syncItem);
        items.add(refreshItem);
        items.add(recommendItem);
        return items;
    }

    private void openPlanInRepeater() {
        String payload = buildSingleMessagePayload("scanner");
        if (payload == null) {
            append("No selected Burp message for plan open.\n");
            return;
        }
        String result = postJson("/api/burp/open-repeater-plan?dispatch=true", payload);
        syncIdentity(result);
        append("Open plan result\n" + result + "\n\n");
    }

    private void syncSelectedTabs() {
        String payload = buildSyncPayload();
        if (payload == null) {
            append("Need one baseline plus one or more selected Repeater tabs.\n");
            return;
        }
        String result = postJson("/api/burp/repeater-sync", payload);
        syncIdentity(result);
        append("Repeater sync result\n" + result + "\n\n");
    }

    private void refreshPanelState() {
        String payload = buildSingleMessagePayload("repeater");
        if (payload == null) {
            payload = "{\"raw_request\":\"\",\"target_url\":\"" + escapeJson(currentTargetUrl) + "\",\"use_burp_mcp_context\":true}";
        }
        StringBuilder path = new StringBuilder("/api/burp/panel-state");
        List<String> params = new ArrayList<>();
        if (!currentIssueId.isEmpty()) {
            params.add("issue_id=" + currentIssueId);
        }
        if (!currentSnapshotId.isEmpty()) {
            params.add("snapshot_id=" + currentSnapshotId);
        }
        if (!params.isEmpty()) {
            path.append("?").append(String.join("&", params));
        }
        String result = postJson(path.toString(), payload);
        syncIdentity(result);
        append("Panel state\n" + result + "\n\n");
    }

    private void showBurpMoves() {
        String payload = buildSingleMessagePayload("scanner");
        if (payload == null) {
            payload = "{\"raw_request\":\"\",\"target_url\":\"" + escapeJson(currentTargetUrl) + "\",\"use_burp_mcp_context\":true}";
        }
        String result = postJson("/api/burp/capability-recommendations", payload);
        append("Burp capability recommendations\n" + result + "\n\n");
    }

    private void refreshModelOptions() {
        String result = getJson("/api/runtime/model-options");
        syncModelState(result);
        append("Model options refreshed.\n");
    }

    private void switchActiveModel() {
        String modelName = switchModelField.getText().trim();
        if (modelName.isEmpty()) {
            append("Enter a model tag before switching.\n");
            return;
        }
        String payload = "{\"model_name\":\"" + escapeJson(modelName) + "\",\"source\":\"burp-panel\"}";
        String result = postJson("/api/runtime/model-selection", payload);
        syncModelState(result);
        append("Active model switched.\n");
    }

    private void resetActiveModel() {
        String result = deleteJson("/api/runtime/model-selection");
        syncModelState(result);
        append("Active model reset to env default.\n");
    }

    private String buildSingleMessagePayload(String sourceTool) {
        if (selectedMessages.length == 0) {
            return null;
        }
        IHttpRequestResponse message = selectedMessages[0];
        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(message);
        String requestText = callbacks.getHelpers().bytesToString(message.getRequest());
        String responseText = callbacks.getHelpers().bytesToString(message.getResponse());
        requestView.setText(requestText);
        requestView.setCaretPosition(0);
        responseView.setText(responseText);
        responseView.setCaretPosition(0);
        String targetUrl = requestInfo.getUrl() != null ? requestInfo.getUrl().toString() : "";
        currentTargetUrl = targetUrl.isEmpty() ? currentTargetUrl : targetUrl;
        return "{"
            + "\"raw_request\":\"" + escapeJson(requestText) + "\","
            + "\"raw_response\":\"" + escapeJson(responseText) + "\","
            + "\"target_url\":\"" + escapeJson(targetUrl) + "\","
            + "\"http_method\":\"" + escapeJson(requestInfo.getMethod()) + "\","
            + "\"source_tool\":\"" + escapeJson(sourceTool) + "\","
            + "\"use_burp_mcp_context\":true"
            + "}";
    }

    private String buildSyncPayload() {
        if (selectedMessages.length == 0) {
            return null;
        }
        String base = buildSingleMessagePayload("repeater");
        String baselineResponse = callbacks.getHelpers().bytesToString(selectedMessages[0].getResponse());
        String baselineRequest = callbacks.getHelpers().bytesToString(selectedMessages[0].getRequest());
        requestView.setText(baselineRequest);
        requestView.setCaretPosition(0);
        responseView.setText(baselineResponse);
        responseView.setCaretPosition(0);
        StringBuilder observations = new StringBuilder("[");
        for (int index = 1; index < selectedMessages.length; index++) {
            IHttpRequestResponse message = selectedMessages[index];
            IRequestInfo info = callbacks.getHelpers().analyzeRequest(message);
            if (index > 1) {
                observations.append(",");
            }
            observations.append("{")
                .append("\"tab_name\":\"selected-tab-").append(index).append("\",")
                .append("\"request_text\":\"").append(escapeJson(callbacks.getHelpers().bytesToString(message.getRequest()))).append("\",")
                .append("\"response_text\":\"").append(escapeJson(callbacks.getHelpers().bytesToString(message.getResponse()))).append("\",")
                .append("\"request_ref\":\"").append(escapeJson(info.getUrl() != null ? info.getUrl().toString() : "")).append("\"")
                .append("}");
        }
        observations.append("]");
        return base.substring(0, base.length() - 1)
            + ",\"baseline_response_text\":\"" + escapeJson(baselineResponse) + "\""
            + ",\"repeater_variant_observations\":" + observations
            + "}";
    }

    private String postJson(String path, String body) {
        try {
            URL url = new URL(baseUrl + path);
            baseUrl = baseUrlField.getText().trim().isEmpty() ? baseUrl : baseUrlField.getText().trim();
            url = new URL(baseUrl + path);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(20000);
            connection.setReadTimeout(20000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            try (OutputStream outputStream = connection.getOutputStream()) {
                outputStream.write(body.getBytes(StandardCharsets.UTF_8));
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder result = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\n");
                }
                return result.toString();
            }
        } catch (Exception exception) {
            return "{\"error\":\"" + escapeJson(exception.toString()) + "\"}";
        }
    }

    private String getJson(String path) {
        try {
            baseUrl = baseUrlField.getText().trim().isEmpty() ? baseUrl : baseUrlField.getText().trim();
            URL url = new URL(baseUrl + path);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(20000);
            connection.setReadTimeout(20000);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder result = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\n");
                }
                return result.toString();
            }
        } catch (Exception exception) {
            return "{\"error\":\"" + escapeJson(exception.toString()) + "\"}";
        }
    }

    private String deleteJson(String path) {
        try {
            baseUrl = baseUrlField.getText().trim().isEmpty() ? baseUrl : baseUrlField.getText().trim();
            URL url = new URL(baseUrl + path);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("DELETE");
            connection.setConnectTimeout(20000);
            connection.setReadTimeout(20000);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder result = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\n");
                }
                return result.toString();
            }
        } catch (Exception exception) {
            return "{\"error\":\"" + escapeJson(exception.toString()) + "\"}";
        }
    }

    private void append(String text) {
        output.append(text);
    }

    private void syncIdentity(String body) {
        currentIssueId = extractJsonValue(body, "issue_id", currentIssueId);
        currentSnapshotId = extractJsonValue(body, "snapshot_id", currentSnapshotId);
        currentTargetUrl = extractJsonValue(body, "target_url", currentTargetUrl);
        issueField.setText(currentIssueId);
        snapshotField.setText(currentSnapshotId);
    }

    private void syncModelState(String body) {
        currentModel = extractJsonValue(body, "current_model", currentModel);
        currentModelField.setText(currentModel);
        if (switchModelField.getText().trim().isEmpty()) {
            switchModelField.setText(extractJsonValue(body, "deep", currentModel));
        }
    }

    private String extractJsonValue(String body, String key, String fallback) {
        String marker = "\"" + key + "\":";
        int start = body.indexOf(marker);
        if (start < 0) {
            return fallback;
        }
        int quote = body.indexOf("\"", start + marker.length());
        int end = quote >= 0 ? body.indexOf("\"", quote + 1) : -1;
        if (quote >= 0 && end > quote) {
            return body.substring(quote + 1, end);
        }
        return fallback;
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n");
    }
}
