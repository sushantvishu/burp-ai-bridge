package com.example.burpaibridge;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BurpAiBridgeExtensionStartupHealthTest {

    @Test
    void startupHealthGateRetriesWhileBackendIsStillPending() {
        StartupHealthGate.Decision decision = StartupHealthGate.decision(false, 3);

        assertFalse(decision.refreshInventory());
        assertTrue(decision.retry());
        assertTrue(decision.backendHealthText().contains("Retrying health check"));
    }

    @Test
    void startupHealthGateDefersInventoryAfterFinalFailedAttempt() {
        StartupHealthGate.Decision decision = StartupHealthGate.decision(false, 1);

        assertFalse(decision.refreshInventory());
        assertFalse(decision.retry());
        assertTrue(decision.backendHealthText().contains("deferred"));
        assertTrue(decision.toolInventoryText().contains("Refresh Inventory"));
    }

    @Test
    void startupHealthGateRefreshesInventoryWhenBackendIsHealthy() {
        StartupHealthGate.Decision decision = StartupHealthGate.decision(true, 5);

        assertTrue(decision.refreshInventory());
        assertFalse(decision.retry());
        assertTrue(decision.backendHealthText().contains("Backend healthy"));
    }
}
