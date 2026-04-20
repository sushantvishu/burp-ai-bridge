package com.example.burpaibridge;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AssessmentRequestContractTest {

    @Test
    void copyAndSerializationPreserveStructuredBurpScannerContext() throws Exception {
        AssessmentRequest request = new AssessmentRequest();
        request.setTargetUrl("https://example.com/Comments.aspx?id=2");
        request.setHttpMethod("POST");
        request.setSourceTool("burp-suite-montoya-scanner-scanner_results-audit-issue");
        request.setUseBurpMcpContext(true);

        Map<String, Object> dashboardIssue = new LinkedHashMap<>();
        dashboardIssue.put("name", "Cross-site scripting (stored)");
        dashboardIssue.put("detail", "The tbComment parameter is copied into the HTML response.");
        dashboardIssue.put("url", "https://example.com/Comments.aspx?id=2");
        request.setBurpDashboardIssue(dashboardIssue);

        Map<String, Object> relatedIssue = new LinkedHashMap<>();
        relatedIssue.put("name", "Input returned in response (stored)");
        relatedIssue.put("detail", "The same comment body is reflected in a stored viewer path.");
        relatedIssue.put("url", "https://example.com/Comments.aspx?id=2");
        request.setBurpRelatedScannerIssues(List.of(relatedIssue));

        Map<String, Object> repeaterRequest = new LinkedHashMap<>();
        repeaterRequest.put("summary", "scanner-request-1");
        repeaterRequest.put("method", "POST");
        repeaterRequest.put("url", "https://example.com/Comments.aspx?id=2");
        request.setRepeaterRequests(List.of(repeaterRequest));

        Map<String, Object> projectSnapshot = new LinkedHashMap<>();
        projectSnapshot.put("selected_profile", "bug-bounty-safe");
        projectSnapshot.put("enabled_tools", List.of("Repeater", "Logger++"));
        request.setProjectConfigSnapshot(projectSnapshot);

        AssessmentRequest copied = request.copy();

        assertTrue(copied.isUseBurpMcpContext());
        assertEquals("Cross-site scripting (stored)", copied.getBurpDashboardIssue().get("name"));
        assertEquals(1, copied.getBurpRelatedScannerIssues().size());
        assertEquals("scanner-request-1", copied.getRepeaterRequests().get(0).get("summary"));
        assertEquals("bug-bounty-safe", copied.getProjectConfigSnapshot().get("selected_profile"));

        ObjectMapper mapper = new ObjectMapper();
        @SuppressWarnings("unchecked")
        Map<String, Object> serialized = mapper.readValue(mapper.writeValueAsString(copied), Map.class);

        assertEquals(Boolean.TRUE, serialized.get("use_burp_mcp_context"));
        assertEquals("Cross-site scripting (stored)", ((Map<?, ?>) serialized.get("burp_dashboard_issue")).get("name"));
        assertEquals(1, ((List<?>) serialized.get("burp_related_scanner_issues")).size());
        assertEquals(1, ((List<?>) serialized.get("repeater_requests")).size());
        assertEquals("bug-bounty-safe", ((Map<?, ?>) serialized.get("project_config_snapshot")).get("selected_profile"));
    }
}
