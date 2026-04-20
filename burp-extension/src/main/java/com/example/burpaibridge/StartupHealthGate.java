package com.example.burpaibridge;

final class StartupHealthGate {
    private StartupHealthGate() {
    }

    static Decision decision(boolean backendHealthy, int attemptsRemaining) {
        if (backendHealthy) {
            return new Decision(
                    true,
                    false,
                    "Backend healthy. Startup inventory refresh is running.",
                    ""
            );
        }
        if (attemptsRemaining > 1) {
            return new Decision(
                    false,
                    true,
                    "Backend startup is still pending. Retrying health check before inventory refresh (" + (attemptsRemaining - 1) + " retries left).",
                    ""
            );
        }
        return new Decision(
                false,
                false,
                "Backend not ready. Automatic startup refresh is deferred until the server is reachable.",
                "Automatic inventory refresh is deferred because the local AI Bridge backend is not ready yet. Start the server, then use Refresh Inventory."
        );
    }

    record Decision(
            boolean refreshInventory,
            boolean retry,
            String backendHealthText,
            String toolInventoryText
    ) {
    }
}
