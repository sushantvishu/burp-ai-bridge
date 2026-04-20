package com.example.burpaibridge;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultsTabSmokeTest {

    @Test
    void updateResultsSelectsSuggestionQueueWorkspaceWhenQueueGuidanceArrives() throws Exception {
        ResultsTab resultsTab = onEdt(() -> new ResultsTab("http://127.0.0.1:8000/api/analyze"));

        AssessmentRequest request = new AssessmentRequest();
        request.setTargetUrl("https://example.com/comments");
        request.setHttpMethod("GET");
        request.setSourceTool("Proxy");
        request.setReviewScopeIncludeClasses(onEdt(resultsTab::reviewScopeIncludeClasses));
        request.setReviewScopeExcludeClasses(List.of());

        AdvisoryResponse response = new AdvisoryResponse();
        response.setAnalysis("Narrow the next step.");
        response.setSuggestionQueue(List.of("Use the queue guidance for the next exact step."));

        resultsTab.updateResults(response, request);
        drainEdt();

        assertEquals("Suggestion Queue", onEdt(resultsTab::selectedWorkspaceTabTitleForTest));
    }

    @Test
    void investigationChatUsesSingleFlightSubmissionAndAddsTimestamps() throws Exception {
        ResultsTab resultsTab = onEdt(() -> new ResultsTab("http://127.0.0.1:8000/api/analyze"));
        AtomicInteger submitCount = new AtomicInteger();

        onEdt(() -> resultsTab.setInvestigationChatSubmitter((sessionId, prompt) -> submitCount.incrementAndGet()));

        AssessmentRequest request = new AssessmentRequest();
        request.setRawRequest("GET /comments HTTP/1.1");
        request.setTargetUrl("https://example.com/comments");
        request.setHttpMethod("GET");
        request.setSourceTool("Repeater");
        request.setReviewScopeIncludeClasses(onEdt(resultsTab::reviewScopeIncludeClasses));
        request.setReviewScopeExcludeClasses(List.of());

        onEdt(() -> resultsTab.restoreInvestigationSession(
                "session-1",
                "Investigation",
                request,
                request.getRawRequest(),
                "",
                true
        ));
        drainEdt();

        onEdt(() -> resultsTab.setInvestigationChatInputForTest("session-1", "Ask for the next exact change."));
        onEdt(() -> resultsTab.submitInvestigationChatForTest("session-1"));
        drainEdt();

        assertEquals(1, submitCount.get());
        assertFalse(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-1")));

        String transcript = onEdt(() -> resultsTab.investigationChatTranscript("session-1"));
        assertTrue(
                transcript.matches("(?s).*\\[\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}] You:\\RAsk for the next exact change\\..*"),
                transcript
        );

        onEdt(() -> resultsTab.setInvestigationChatInputForTest("session-1", "Try to submit again."));
        onEdt(() -> resultsTab.submitInvestigationChatForTest("session-1"));
        drainEdt();

        assertEquals(1, submitCount.get());
        assertTrue(onEdt(() -> resultsTab.investigationStatusTextForTest("session-1")).contains("already running"));
    }

    @Test
    void investigationChatRunsIndependentlyPerSession() throws Exception {
        ResultsTab resultsTab = onEdt(() -> new ResultsTab("http://127.0.0.1:8000/api/analyze"));
        AtomicInteger submitCount = new AtomicInteger();

        onEdt(() -> resultsTab.setInvestigationChatSubmitter((sessionId, prompt) -> submitCount.incrementAndGet()));

        AssessmentRequest request = new AssessmentRequest();
        request.setRawRequest("GET /comments HTTP/1.1");
        request.setTargetUrl("https://example.com/comments");
        request.setHttpMethod("GET");
        request.setSourceTool("Repeater");
        request.setReviewScopeIncludeClasses(onEdt(resultsTab::reviewScopeIncludeClasses));
        request.setReviewScopeExcludeClasses(List.of());

        onEdt(() -> resultsTab.restoreInvestigationSession("session-a", "Investigation A", request, request.getRawRequest(), "", true));
        onEdt(() -> resultsTab.restoreInvestigationSession("session-b", "Investigation B", request, request.getRawRequest(), "", false));
        drainEdt();

        onEdt(() -> resultsTab.setInvestigationChatInputForTest("session-a", "First investigation follow-up."));
        onEdt(() -> resultsTab.submitInvestigationChatForTest("session-a"));
        drainEdt();

        assertFalse(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-a")));
        assertTrue(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-b")));

        onEdt(() -> resultsTab.setInvestigationChatInputForTest("session-b", "Second investigation follow-up."));
        onEdt(() -> resultsTab.submitInvestigationChatForTest("session-b"));
        drainEdt();

        assertEquals(2, submitCount.get());
        assertFalse(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-a")));
        assertFalse(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-b")));

        AdvisoryResponse response = new AdvisoryResponse();
        response.setPrimaryNextAction("Keep the same request shape and compare one controlled change.");
        onEdt(() -> resultsTab.showInvestigationResult("session-a", request, response));
        drainEdt();

        assertTrue(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-a")));
        assertFalse(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-b")));

        onEdt(() -> resultsTab.showInvestigationError("session-b", "Synthetic failure for smoke coverage."));
        drainEdt();

        assertTrue(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-b")));
    }

    @Test
    void investigationWorkflowNotesCaptureRecentTurnsForFollowUpContext() throws Exception {
        ResultsTab resultsTab = onEdt(() -> new ResultsTab("http://127.0.0.1:8000/api/analyze"));
        onEdt(() -> resultsTab.setInvestigationChatSubmitter((sessionId, prompt) -> {
        }));

        AssessmentRequest request = new AssessmentRequest();
        request.setRawRequest("GET /comments?id=1 HTTP/1.1");
        request.setTargetUrl("https://example.com/comments?id=1");
        request.setHttpMethod("GET");
        request.setSourceTool("Scanner");
        request.setToolResultsText("Selected Burp audit issue(s) for https://example.com/comments: Input returned in response (reflected).");
        request.setReviewScopeIncludeClasses(onEdt(resultsTab::reviewScopeIncludeClasses));
        request.setReviewScopeExcludeClasses(List.of());

        onEdt(() -> resultsTab.restoreInvestigationSession(
                "session-2",
                "Scanner Investigation",
                request,
                request.getRawRequest(),
                "",
                true
        ));
        drainEdt();

        onEdt(() -> resultsTab.setInvestigationChatInputForTest("session-2", "Tell me the next exact reflected-XSS check."));
        onEdt(() -> resultsTab.submitInvestigationChatForTest("session-2"));
        drainEdt();

        AdvisoryResponse response = new AdvisoryResponse();
        response.setPrimaryNextAction("Change only the reflected input value and compare the output encoding in the same response location.");
        response.setRequestPlan(List.of("Keep one baseline tab.", "Change only the reflected value.", "Compare encoding and placement."));
        response.setConfirmationPlaybooks(List.of("Check whether the response context stays HTML text or moves into an attribute or script context."));
        response.setSuggestionQueue(List.of("Try one harmless reflected marker and compare how it is encoded."));

        onEdt(() -> resultsTab.showInvestigationResult("session-2", request, response));
        drainEdt();

        List<String> notes = onEdt(() -> resultsTab.investigationWorkflowNotes("session-2"));

        assertTrue(notes.stream().anyMatch(item -> item.contains("Last AI primary next action:")), notes.toString());
        assertTrue(notes.stream().anyMatch(item -> item.contains("Transcript [") && item.contains("You")), notes.toString());
        assertTrue(notes.stream().anyMatch(item -> item.contains("Transcript [") && item.contains("AI Bridge")), notes.toString());
    }

    @Test
    void restoreInvestigationSessionPreservesStructuredTranscriptAndStatus() throws Exception {
        ResultsTab resultsTab = onEdt(() -> new ResultsTab("http://127.0.0.1:8000/api/analyze"));

        AssessmentRequest request = new AssessmentRequest();
        request.setRawRequest("GET /comments?id=1 HTTP/1.1");
        request.setTargetUrl("https://example.com/comments?id=1");
        request.setHttpMethod("GET");
        request.setSourceTool("Scanner");
        request.setReviewScopeIncludeClasses(onEdt(resultsTab::reviewScopeIncludeClasses));
        request.setReviewScopeExcludeClasses(List.of());

        List<ResultsTab.InvestigationTranscriptState> transcriptStates = new ArrayList<>();
        ResultsTab.InvestigationTranscriptState operatorState = new ResultsTab.InvestigationTranscriptState();
        operatorState.timestamp = "2026-04-11 22:15:00";
        operatorState.speaker = "You";
        operatorState.message = "Tell me the next exact reflected-XSS check.";
        transcriptStates.add(operatorState);

        ResultsTab.InvestigationTranscriptState assistantState = new ResultsTab.InvestigationTranscriptState();
        assistantState.timestamp = "2026-04-11 22:15:05";
        assistantState.speaker = "AI Bridge";
        assistantState.message = "Keep the same reflection point and compare output encoding.";
        transcriptStates.add(assistantState);

        List<ResultsTab.InvestigationNotebookEntryState> notebookStates = new ArrayList<>();
        ResultsTab.InvestigationNotebookEntryState notebookState = new ResultsTab.InvestigationNotebookEntryState();
        notebookState.timestamp = "2026-04-11 22:15:05";
        notebookState.kind = "assistant_guidance";
        notebookState.title = "AI guidance update";
        notebookState.details = "Primary next action: Keep the same reflection point and compare output encoding.";
        notebookStates.add(notebookState);

        onEdt(() -> resultsTab.restoreInvestigationSession(
                "session-3",
                "Restored Session",
                request,
                request.getRawRequest(),
                "",
                transcriptStates,
                notebookStates,
                "AI response ready. Edit the draft request or ask for the next exact change.",
                true
        ));
        drainEdt();

        assertEquals(
                "AI response ready. Edit the draft request or ask for the next exact change.",
                onEdt(() -> resultsTab.investigationStatus("session-3"))
        );
        assertEquals(2, onEdt(() -> resultsTab.investigationTranscriptEntries("session-3").size()));

        String transcript = onEdt(() -> resultsTab.investigationChatTranscript("session-3"));
        assertTrue(transcript.contains("[2026-04-11 22:15:00] You:"), transcript);
        assertTrue(transcript.contains("[2026-04-11 22:15:05] AI Bridge:"), transcript);
        assertTrue(onEdt(() -> resultsTab.investigationCaseNotebookText("session-3")).contains("AI guidance update"));
    }

    @Test
    void investigationCaseNotebookKeepsLongerMultiTurnSummary() throws Exception {
        ResultsTab resultsTab = onEdt(() -> new ResultsTab("http://127.0.0.1:8000/api/analyze"));
        onEdt(() -> resultsTab.setInvestigationChatSubmitter((sessionId, prompt) -> {
        }));

        AssessmentRequest request = new AssessmentRequest();
        request.setRawRequest("GET /comments?id=1 HTTP/1.1");
        request.setTargetUrl("https://example.com/comments?id=1");
        request.setHttpMethod("GET");
        request.setSourceTool("Scanner");
        request.setToolResultsText("Selected Burp audit issue(s) for https://example.com/comments: Input returned in response (reflected).");
        request.setReviewScopeIncludeClasses(onEdt(resultsTab::reviewScopeIncludeClasses));
        request.setReviewScopeExcludeClasses(List.of());

        onEdt(() -> resultsTab.restoreInvestigationSession(
                "session-4",
                "Long Investigation",
                request,
                request.getRawRequest(),
                "",
                true
        ));
        drainEdt();

        onEdt(() -> resultsTab.setInvestigationChatInputForTest("session-4", "First follow-up: tell me the next reflected-XSS confirmation step."));
        onEdt(() -> resultsTab.submitInvestigationChatForTest("session-4"));
        drainEdt();

        AdvisoryResponse firstResponse = new AdvisoryResponse();
        firstResponse.setPrimaryNextAction("Keep the same reflection point and compare encoding across one harmless marker.");
        firstResponse.setRequestPlan(List.of("Keep the baseline tab.", "Change only the reflected marker.", "Compare the output encoding."));
        firstResponse.setSuggestionQueue(List.of("If the marker stays reflected, compare whether it moves into an attribute or script context."));
        onEdt(() -> resultsTab.showInvestigationResult("session-4", request, firstResponse));
        drainEdt();

        onEdt(() -> resultsTab.setInvestigationChatInputForTest("session-4", "Second follow-up: now tell me the next impact-oriented check."));
        onEdt(() -> resultsTab.submitInvestigationChatForTest("session-4"));
        drainEdt();

        AdvisoryResponse secondResponse = new AdvisoryResponse();
        secondResponse.setPrimaryNextAction("Confirm whether the reflection can reach a more dangerous rendering context before trying broader payloads.");
        secondResponse.setRequestPlan(List.of("Reuse the same endpoint.", "Try one context-shaping but harmless input change.", "Compare placement and encoding again."));
        secondResponse.setSuggestionQueue(List.of("If the context changes, keep the same insertion point and prove the delta is stable."));
        onEdt(() -> resultsTab.showInvestigationResult("session-4", request, secondResponse));
        drainEdt();

        String notebook = onEdt(() -> resultsTab.investigationCaseNotebookText("session-4"));
        assertTrue(notebook.contains("Persistent notebook timeline"), notebook);
        assertTrue(notebook.contains("First follow-up"), notebook);
        assertTrue(notebook.contains("Second follow-up"), notebook);
        assertTrue(notebook.contains("AI guidance update"), notebook);
    }

    @Test
    void updateResultsSelectsToolingTabByTitleWhenOnlyManualCommandsArrive() throws Exception {
        ResultsTab resultsTab = onEdt(() -> new ResultsTab("http://127.0.0.1:8000/api/analyze"));

        AssessmentRequest request = new AssessmentRequest();
        request.setTargetUrl("https://example.com/comments");
        request.setHttpMethod("GET");
        request.setSourceTool("Proxy");
        request.setReviewScopeIncludeClasses(onEdt(resultsTab::reviewScopeIncludeClasses));
        request.setReviewScopeExcludeClasses(List.of());

        AdvisoryResponse response = new AdvisoryResponse();
        response.setAnalysis("Use tooling next.");
        response.setManualCommands(List.of("curl https://example.com/comments"));

        onEdt(() -> resultsTab.updateResults(response, request));
        drainEdt();

        assertEquals("Tooling", onEdt(resultsTab::selectedResultTabTitleForTest));
    }

    @Test
    void operatorScopedInvestigationFollowUpOnlyLocksTheTargetSession() throws Exception {
        ResultsTab resultsTab = onEdt(() -> new ResultsTab("http://127.0.0.1:8000/api/analyze"));

        AssessmentRequest request = new AssessmentRequest();
        request.setRawRequest("GET /comments HTTP/1.1");
        request.setTargetUrl("https://example.com/comments");
        request.setHttpMethod("GET");
        request.setSourceTool("Repeater");
        request.setReviewScopeIncludeClasses(onEdt(resultsTab::reviewScopeIncludeClasses));
        request.setReviewScopeExcludeClasses(List.of());

        onEdt(() -> resultsTab.restoreInvestigationSession("session-x", "Investigation X", request, request.getRawRequest(), "", true));
        onEdt(() -> resultsTab.restoreInvestigationSession("session-y", "Investigation Y", request, request.getRawRequest(), "", false));
        drainEdt();

        onEdt(() -> resultsTab.showInvestigationFollowUpSubmitting("session-x"));
        drainEdt();

        assertFalse(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-x")));
        assertTrue(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-y")));

        onEdt(() -> resultsTab.showInvestigationFollowUpCanceled("session-x", "Stopped locally."));
        drainEdt();

        assertTrue(onEdt(() -> resultsTab.investigationSubmitEnabledForTest("session-x")));
        assertEquals("Stopped locally.", onEdt(() -> resultsTab.investigationStatusTextForTest("session-x")));
    }

    private static void drainEdt() throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            return;
        }
        SwingUtilities.invokeAndWait(() -> {
        });
    }

    private static void onEdt(ThrowingRunnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
            return;
        }
        final Exception[] failure = new Exception[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                action.run();
            } catch (Exception exception) {
                failure[0] = exception;
            }
        });
        if (failure[0] != null) {
            throw failure[0];
        }
    }

    private static <T> T onEdt(Callable<T> action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            return action.call();
        }
        final Object[] value = new Object[1];
        final Exception[] failure = new Exception[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                value[0] = action.call();
            } catch (Exception exception) {
                failure[0] = exception;
            }
        });
        if (failure[0] != null) {
            throw failure[0];
        }
        @SuppressWarnings("unchecked")
        T cast = (T) value[0];
        return cast;
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
