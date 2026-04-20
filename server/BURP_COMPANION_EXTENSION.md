# Burp Companion Extension

This repo now includes Burp-side companion templates for driving the AI Bridge panel loop from inside Burp Suite Pro.

Files:

- `samples/burp/BurpAiBridgePanel.py`
- `samples/burp/BurpAiBridgePanel.java`
- `samples/burp/BurpAiBridgeMontoyaExtension.java`
- `burp_assets/custom_scan_checks/`
- `burp_assets/bambda/`

What the Burp-side panel action should do:

1. Read the currently selected Burp Scanner issue or Repeater tab.
2. Extract:
   - `raw_request`
   - `raw_response`
   - `target_url`
   - `http_method`
   - Burp issue ID if available
   - Burp snapshot/workflow identifiers if already known
3. Send one of these actions to the bridge:
   - `/api/burp/open-repeater-plan` when new Repeater tabs are needed
   - `/api/burp/repeater-sync` after one or more Repeater tabs were sent and have responses
   - `/api/burp/panel-state` to refresh the UI state for the selected issue
   - `/api/burp/capability-recommendations` to get the best next Burp feature, starter custom check/Bambda pack, and bounded external tool suggestions
   - `/api/runtime/model-options` when the Burp-side settings panel needs the exact installed Ollama tags
   - `/api/runtime/model-selection` when the operator switches the active Ollama model from the Burp-side settings panel
4. Render:
   - workflow status
   - strongest delta
   - missing evidence
   - best next tab
   - matched guidance packs
   - why the top guidance pack is influencing the current step
   - the active guidance merge policy
   - companion actions available
5. Keep the user in control. The panel should not auto-send Repeater requests or mutate traffic without an explicit click.

Recommended panel buttons:

- `Open Plan in Repeater`
- `Sync Selected Tabs`
- `Refresh Panel State`

Recommended settings controls:

- `Refresh Model Options`
- `Switch Active Model`
- `Reset To Env Model`
- `Show Burp Capability Recommendations`

Recommended context-menu actions:

- `AI Bridge: Open plan in Repeater`
- `AI Bridge: Sync selected tabs`
- `AI Bridge: Refresh panel state`

Expected loop:

1. Select Scanner issue.
2. Click `Open Plan in Repeater`.
3. Send the generated Repeater tabs.
4. Select the tested tabs.
5. Click `Sync Selected Tabs`.
6. Review the refreshed panel state and the best next tab.

The full operator workflow for this loop, including promotion gates and report-or-drop rules, is in `BURP_SCANNER_CASE_PLAYBOOK.md`.

Notes:

- The Jython sample is the fastest way to prove the flow in Burp.
- The Montoya Java sample is the better long-term path if you want a packaged Burp extension.
- These samples assume the AI Bridge server is running on `http://127.0.0.1:8000`.
