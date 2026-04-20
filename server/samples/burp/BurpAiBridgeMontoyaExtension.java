package server.samples.burp;

/*
 * Montoya-native Burp AI Bridge companion sketch.
 *
 * This is a starter file that shows the preferred Burp Suite Pro extension
 * direction: Java + Montoya API. It is intentionally minimal and should be
 * adapted into a proper Gradle/Maven Burp extension project before packaging.
 */

// Example imports for a real implementation:
// import burp.api.montoya.BurpExtension;
// import burp.api.montoya.MontoyaApi;
// import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
// import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
// import burp.api.montoya.ui.UserInterface;

public final class BurpAiBridgeMontoyaExtension {
    private static final String BRIDGE_BASE_URL = "http://127.0.0.1:8000";

    /*
     * A real Montoya implementation should:
     *
     * 1. Register a suite tab or docked panel.
     * 2. Register context-menu items for:
     *    - Open plan in Repeater
     *    - Sync selected tabs
     *    - Refresh panel state
     *    - Get Burp capability recommendations
     * 3. Read the selected request, response, issue metadata, and highlights.
     * 4. POST that context to:
     *    - /api/burp/open-repeater-plan
     *    - /api/burp/repeater-sync
     *    - /api/burp/panel-state
     *    - /api/burp/capability-recommendations
     * 5. Render:
     *    - next step
     *    - proof level
     *    - missing artifact
     *    - best Burp feature to try next
     *    - starter custom check / Bambda pack paths
     *
     * Keep all request sending user-triggered. Do not auto-send traffic.
     */

    public String companionSummary() {
        return "Montoya companion should use " + BRIDGE_BASE_URL
            + " and keep the operator in explicit control of every Burp action.";
    }
}
