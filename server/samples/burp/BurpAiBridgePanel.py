#
# Burp AI Bridge companion panel sketch for Burp Suite Pro + Jython 2.7.
# This is a practical starter template, not a packaged production extension.
#

from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory
from java.awt import BorderLayout
from java.awt import GridLayout
from java.awt import Font
from java.util import ArrayList
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JMenuItem
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import ScrollPaneConstants
from javax.swing import SwingUtilities
import json
import urllib2


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._base_url = "http://127.0.0.1:8000"
        self._selected_messages = []
        self._current_issue_id = ""
        self._current_snapshot_id = ""
        self._current_target_url = ""
        self._current_model = ""

        callbacks.setExtensionName("Burp AI Bridge Companion")
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        self._panel = JPanel(BorderLayout())
        mono = Font("Consolas", Font.PLAIN, 12)
        self._output = JTextArea("", 18, 100)
        self._output.setEditable(False)
        self._output.setLineWrap(False)
        self._output.setWrapStyleWord(False)
        self._output.setFont(mono)
        self._request_view = JTextArea("", 16, 100)
        self._request_view.setEditable(False)
        self._request_view.setLineWrap(False)
        self._request_view.setWrapStyleWord(False)
        self._request_view.setFont(mono)
        self._response_view = JTextArea("", 16, 100)
        self._response_view.setEditable(False)
        self._response_view.setLineWrap(False)
        self._response_view.setWrapStyleWord(False)
        self._response_view.setFont(mono)
        controls = JPanel(GridLayout(2, 1))
        toolbar = JPanel()
        info = JPanel()

        self._base_url_field = JTextField(self._base_url, 28)
        self._issue_field = JTextField("", 18)
        self._snapshot_field = JTextField("", 18)
        self._current_model_field = JTextField("", 18)
        self._switch_model_field = JTextField("", 18)
        self._issue_field.setEditable(False)
        self._snapshot_field.setEditable(False)
        self._current_model_field.setEditable(False)

        open_button = JButton("Open Plan in Repeater", actionPerformed=self._open_plan_action)
        sync_button = JButton("Sync Selected Tabs", actionPerformed=self._sync_tabs_action)
        refresh_button = JButton("Refresh Panel State", actionPerformed=self._refresh_panel_action)
        recommend_button = JButton("Show Burp Moves", actionPerformed=self._recommend_burp_moves_action)
        refresh_models_button = JButton("Refresh Model Options", actionPerformed=self._refresh_model_options_action)
        switch_model_button = JButton("Switch Active Model", actionPerformed=self._switch_model_action)
        reset_model_button = JButton("Reset Model", actionPerformed=self._reset_model_action)

        toolbar.add(JLabel("Bridge URL"))
        toolbar.add(self._base_url_field)
        toolbar.add(open_button)
        toolbar.add(sync_button)
        toolbar.add(refresh_button)
        toolbar.add(recommend_button)
        toolbar.add(refresh_models_button)
        info.add(JLabel("Issue"))
        info.add(self._issue_field)
        info.add(JLabel("Snapshot"))
        info.add(self._snapshot_field)
        info.add(JLabel("Model"))
        info.add(self._current_model_field)
        info.add(JLabel("Switch To"))
        info.add(self._switch_model_field)
        info.add(switch_model_button)
        info.add(reset_model_button)

        controls.add(toolbar)
        controls.add(info)
        self._panel.add(controls, BorderLayout.NORTH)
        output_scroll = JScrollPane(self._output)
        output_scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        output_scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED)
        request_scroll = JScrollPane(self._request_view)
        request_scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        request_scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED)
        response_scroll = JScrollPane(self._response_view)
        response_scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        response_scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED)

        tabs = JTabbedPane()
        tabs.addTab("Bridge Output", output_scroll)
        tabs.addTab("Selected Request", request_scroll)
        tabs.addTab("Selected Response", response_scroll)

        self._panel.add(tabs, BorderLayout.CENTER)
        self._append("Burp AI Bridge companion loaded.\n")

    def getTabCaption(self):
        return "AI Bridge"

    def getUiComponent(self):
        return self._panel

    def createMenuItems(self, invocation):
        self._selected_messages = list(invocation.getSelectedMessages() or [])
        menu = ArrayList()
        menu.add(JMenuItem("AI Bridge: Open plan in Repeater", actionPerformed=lambda event: self._open_plan_action(event)))
        menu.add(JMenuItem("AI Bridge: Sync selected tabs", actionPerformed=lambda event: self._sync_tabs_action(event)))
        menu.add(JMenuItem("AI Bridge: Refresh panel state", actionPerformed=lambda event: self._refresh_panel_action(event)))
        menu.add(JMenuItem("AI Bridge: Show Burp moves", actionPerformed=lambda event: self._recommend_burp_moves_action(event)))
        return menu

    def _open_plan_action(self, _event):
        payload = self._build_single_message_payload(source_tool="scanner")
        if not payload:
            self._append("No Burp message selected for plan open.\n")
            return
        result = self._post_json("/api/burp/open-repeater-plan?dispatch=true", payload)
        self._sync_identity(result)
        self._render_panel_state("Open plan result", result)

    def _sync_tabs_action(self, _event):
        payload = self._build_sync_payload()
        if not payload:
            self._append("Need at least one selected Repeater request/response to sync.\n")
            return
        result = self._post_json("/api/burp/repeater-sync", payload)
        self._sync_identity(result)
        self._render_panel_state("Repeater sync result", result)

    def _refresh_panel_action(self, _event):
        payload = self._build_single_message_payload(source_tool="repeater") or {
            "raw_request": "",
            "target_url": self._current_target_url,
            "use_burp_mcp_context": True,
        }
        query = []
        if self._current_issue_id:
            query.append("issue_id=" + self._current_issue_id)
        if self._current_snapshot_id:
            query.append("snapshot_id=" + self._current_snapshot_id)
        endpoint = "/api/burp/panel-state"
        if query:
            endpoint += "?" + "&".join(query)
        result = self._post_json(endpoint, payload)
        self._sync_identity(result)
        self._render_panel_state("Panel state", result)

    def _recommend_burp_moves_action(self, _event):
        payload = self._build_single_message_payload(source_tool="scanner") or {
            "raw_request": "",
            "target_url": self._current_target_url,
            "use_burp_mcp_context": True,
        }
        result = self._post_json("/api/burp/capability-recommendations", payload)
        self._render_capability_recommendations(result)

    def _refresh_model_options_action(self, _event):
        result = self._get_json("/api/runtime/model-options")
        self._sync_model_state(result)
        self._append("Model options refreshed.\n")

    def _switch_model_action(self, _event):
        model_name = self._switch_model_field.getText().strip()
        if not model_name:
            self._append("Enter a model tag before switching.\n")
            return
        result = self._post_json("/api/runtime/model-selection", {"model_name": model_name, "source": "burp-panel"})
        self._sync_model_state(result)
        self._append("Active model switched to %s.\n" % result.get("current_model", model_name))

    def _reset_model_action(self, _event):
        result = self._delete_json("/api/runtime/model-selection")
        self._sync_model_state(result)
        self._append("Active model reset to env default.\n")

    def _build_single_message_payload(self, source_tool="repeater"):
        if not self._selected_messages:
            return None
        message = self._selected_messages[0]
        request_text = self._helpers.bytesToString(message.getRequest() or "")
        response_text = self._helpers.bytesToString(message.getResponse() or "")
        self._request_view.setText(request_text)
        self._request_view.setCaretPosition(0)
        self._response_view.setText(response_text)
        self._response_view.setCaretPosition(0)
        analyzed = self._helpers.analyzeRequest(message)
        url = str(analyzed.getUrl()) if analyzed and analyzed.getUrl() else ""
        method = analyzed.getMethod() if analyzed else ""
        self._current_target_url = url or self._current_target_url
        return {
            "raw_request": request_text,
            "raw_response": response_text,
            "target_url": url,
            "http_method": method,
            "source_tool": source_tool,
            "use_burp_mcp_context": True,
        }

    def _build_sync_payload(self):
        if not self._selected_messages:
            return None

        baseline = self._helpers.bytesToString(self._selected_messages[0].getResponse() or "")
        if self._selected_messages:
            first_request = self._helpers.bytesToString(self._selected_messages[0].getRequest() or "")
            self._request_view.setText(first_request)
            self._request_view.setCaretPosition(0)
            self._response_view.setText(baseline)
            self._response_view.setCaretPosition(0)
        observations = []
        for index, message in enumerate(self._selected_messages[1:]):
            analyzed = self._helpers.analyzeRequest(message)
            observations.append({
                "tab_name": "selected-tab-%d" % (index + 1),
                "request_text": self._helpers.bytesToString(message.getRequest() or ""),
                "response_text": self._helpers.bytesToString(message.getResponse() or ""),
                "request_ref": str(analyzed.getUrl()) if analyzed and analyzed.getUrl() else "",
            })

        payload = self._build_single_message_payload(source_tool="repeater") or {}
        payload["baseline_response_text"] = baseline
        payload["repeater_variant_observations"] = observations
        return payload

    def _post_json(self, path, payload):
        self._base_url = self._base_url_field.getText().strip() or self._base_url
        url = self._base_url.rstrip("/") + path
        body = json.dumps(payload)
        request = urllib2.Request(url, body, {"Content-Type": "application/json"})
        response = urllib2.urlopen(request, timeout=20)
        return json.loads(response.read())

    def _get_json(self, path):
        self._base_url = self._base_url_field.getText().strip() or self._base_url
        url = self._base_url.rstrip("/") + path
        response = urllib2.urlopen(url, timeout=20)
        return json.loads(response.read())

    def _delete_json(self, path):
        self._base_url = self._base_url_field.getText().strip() or self._base_url
        url = self._base_url.rstrip("/") + path
        request = urllib2.Request(url, headers={"Content-Type": "application/json"})
        request.get_method = lambda: "DELETE"
        response = urllib2.urlopen(request, timeout=20)
        return json.loads(response.read())

    def _render_panel_state(self, title, data):
        lines = [title]
        if data.get("workflow_status"):
            lines.append("Workflow: %s" % data.get("workflow_status"))
        best = data.get("best_next_tab") or {}
        if best.get("tab_name"):
            lines.append("Best next tab: %s" % best.get("tab_name"))
        diff = data.get("diff_summary") or data.get("diff") or {}
        if diff.get("summary"):
            lines.append("Diff: %s" % diff.get("summary"))
        guidance = data.get("guidance_hits") or []
        if guidance:
            top = guidance[0]
            lines.append("Matched pack: %s (%s)" % (top.get("name", ""), top.get("influence_reason", "")))
        workflow = data.get("workflow") or {}
        learning = workflow.get("mutation_learning_summary") or {}
        if learning.get("summary"):
            lines.append("Mutation learning: %s" % learning.get("summary"))
        review_summary = data.get("review_dataset_summary", "")
        if review_summary:
            lines.append("Review dataset: %s" % review_summary)
        severity = data.get("severity_assessment") or {}
        calibration = severity.get("confidence_calibration") or {}
        if calibration.get("level"):
            lines.append("Confidence: %s (%.2f)" % (calibration.get("level"), calibration.get("score", 0.0)))
        notes = data.get("notes") or []
        for note in notes[:4]:
            lines.append("- %s" % note)
        capability_recs = data.get("burp_capability_recommendations") or []
        for rec in capability_recs[:3]:
            lines.append("Burp move: %s - %s" % (rec.get("tool", ""), rec.get("why", "")))
        lines.append("")
        lines.append(json.dumps(data, indent=2, sort_keys=True))
        lines.append("")
        self._append("\n".join(lines))

    def _render_capability_recommendations(self, data):
        lines = ["Burp capability recommendations"]
        lines.append("Context source: %s" % data.get("primary_context_source", ""))
        for rec in data.get("recommendations", [])[:5]:
            lines.append("%s: %s" % (rec.get("tool", ""), rec.get("why", "")))
            lines.append("  Step: %s" % rec.get("manual_step", ""))
            lines.append("  Signal: %s" % rec.get("expected_signal", ""))
            lines.append("  Stop: %s" % rec.get("stop_when", ""))
        starter_assets = data.get("starter_assets") or {}
        if starter_assets:
            lines.append("Starter assets available: %s" % ", ".join(sorted(starter_assets.keys())))
        tools = data.get("external_tool_recommendations") or []
        for tool in tools[:4]:
            lines.append("External tool: %s (%s)" % (tool.get("tool", ""), tool.get("package_hint", "")))
        lines.append("")
        lines.append(json.dumps(data, indent=2, sort_keys=True))
        lines.append("")
        self._append("\n".join(lines))

    def _sync_identity(self, data):
        self._current_issue_id = data.get("issue_id", "") or self._current_issue_id
        self._current_snapshot_id = data.get("snapshot_id", "") or self._current_snapshot_id
        self._current_target_url = data.get("target_url", "") or self._current_target_url
        self._issue_field.setText(self._current_issue_id)
        self._snapshot_field.setText(self._current_snapshot_id)

    def _sync_model_state(self, data):
        current_model = data.get("current_model", "") or self._current_model
        if current_model:
            self._current_model = current_model
            self._current_model_field.setText(current_model)
        switch_targets = data.get("switch_targets") or {}
        if not self._switch_model_field.getText().strip():
            self._switch_model_field.setText(switch_targets.get("deep", "") or current_model)

    def _append(self, text):
        def update():
            self._output.append(text + ("\n" if not text.endswith("\n") else ""))
        SwingUtilities.invokeLater(update)
