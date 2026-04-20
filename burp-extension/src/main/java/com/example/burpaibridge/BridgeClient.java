package com.example.burpaibridge;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class BridgeClient {
    private static final Duration SUBMIT_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration STATUS_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration MAX_JOB_WAIT = Duration.ofMinutes(15);
    private static final long POLL_INTERVAL_MILLIS = 5000L;
    private static final int ANALYSIS_WORKER_THREADS = 4;
    private static final int AUXILIARY_WORKER_THREADS = 4;

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final ExecutorService analysisExecutorService;
    private final ExecutorService auxiliaryExecutorService;

    public BridgeClient() {
        this.analysisExecutorService = newFixedDaemonPool("burp-ai-bridge-analysis", ANALYSIS_WORKER_THREADS);
        this.auxiliaryExecutorService = newFixedDaemonPool("burp-ai-bridge-aux", AUXILIARY_WORKER_THREADS);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .version(HttpClient.Version.HTTP_1_1)
                .executor(auxiliaryExecutorService)
                .build();
        this.mapper = new ObjectMapper();
        this.mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private ExecutorService newFixedDaemonPool(String threadPrefix, int threadCount) {
        return Executors.newFixedThreadPool(threadCount, runnable -> {
            Thread thread = new Thread(runnable, threadPrefix);
            thread.setDaemon(true);
            return thread;
        });
    }

    public CompletableFuture<AdvisoryResponse> analyzeAsync(
            String endpointUrl,
            AssessmentRequest payload,
            Consumer<AnalysisJobStatus> progressCallback
    ) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return analyze(endpointUrl, payload, progressCallback);
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, analysisExecutorService);
    }

    public CompletableFuture<Void> submitFeedbackAsync(
            String endpointUrl,
            String jobId,
            String label,
            String notes
    ) {
        return CompletableFuture.runAsync(() -> {
            try {
                submitFeedback(endpointUrl, jobId, label, notes);
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, auxiliaryExecutorService);
    }

    public CompletableFuture<KaliToolInventoryResponse> fetchToolInventoryAsync(String endpointUrl, boolean refresh) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return fetchToolInventory(endpointUrl, refresh);
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, auxiliaryExecutorService);
    }

    public CompletableFuture<Boolean> checkRuntimeHealthAsync(String endpointUrl) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return checkRuntimeHealth(endpointUrl);
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, auxiliaryExecutorService);
    }

    public CompletableFuture<List<BCheckCatalogEntry>> fetchBcheckCatalogAsync(String endpointUrl) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return fetchBcheckCatalog(endpointUrl);
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, auxiliaryExecutorService);
    }

    public CompletableFuture<BCheckContentResponse> fetchBcheckContentAsync(String endpointUrl, String relativePath) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return fetchBcheckContent(endpointUrl, relativePath);
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, auxiliaryExecutorService);
    }

    public CompletableFuture<PhaseHistoryResponse> fetchPhaseHistoryAsync(String endpointUrl, String jobId, String phase, int limit) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return fetchPhaseHistory(endpointUrl, jobId, phase, limit);
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, auxiliaryExecutorService);
    }

    public CompletableFuture<AnalysisReasoningResponse> fetchReasoningSummaryAsync(String endpointUrl, String jobId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return fetchReasoningSummary(endpointUrl, jobId);
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, auxiliaryExecutorService);
    }

    public AdvisoryResponse analyze(
            String endpointUrl,
            AssessmentRequest payload,
            Consumer<AnalysisJobStatus> progressCallback
    ) throws IOException, InterruptedException {
        String normalizedEndpoint = normalizeEndpoint(endpointUrl);
        String jsonPayload = mapper.writeValueAsString(payload);
        try {
            PreparedBurpExportResponse prepared = prepareBurpExport(normalizedEndpoint, payload);
            Map<String, Object> normalizedPayload = prepared.getPayload();
            if (!normalizedPayload.isEmpty()) {
                jsonPayload = mapper.writeValueAsString(normalizedPayload);
            }
        } catch (IOException ignored) {
            // Keep compatibility with older bridge versions by falling back to the raw request payload.
        }

        AnalysisJobAccepted accepted = submitJob(normalizedEndpoint, jsonPayload);
        notifyProgress(progressCallback, toStatus(accepted));

        long startedAt = System.nanoTime();
        String statusUrl = buildJobStatusUrl(normalizedEndpoint, accepted.getJobId());

        while (Duration.ofNanos(System.nanoTime() - startedAt).compareTo(MAX_JOB_WAIT) < 0) {
            Thread.sleep(POLL_INTERVAL_MILLIS);
            AnalysisJobStatus status = getJobStatus(statusUrl);
            notifyProgress(progressCallback, status);

            if (status.isCompleted()) {
                if (status.getResult() == null) {
                    throw new IOException("Analysis job completed without a result payload.");
                }
                return status.getResult();
            }
            if (status.isFailed()) {
                String message = status.getError().isBlank() ? status.getStatusMessage() : status.getError();
                throw new IOException(message == null || message.isBlank() ? "Analysis job failed." : message);
            }
        }

        throw new IOException("Analysis job exceeded the maximum wait time of " + MAX_JOB_WAIT.toMinutes() + " minutes.");
    }

    private AnalysisJobAccepted submitJob(String endpointUrl, String jsonPayload) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(buildJobsUrl(endpointUrl)))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", "Burp-AI-Bridge/0.2.0")
                .timeout(SUBMIT_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge job submission returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
        try {
            return mapper.readValue(response.body(), AnalysisJobAccepted.class);
        } catch (IOException exception) {
            throw new IOException(
                    "Bridge job submission returned HTTP 200 but the response could not be parsed: " + truncate(response.body()),
                    exception
            );
        }
    }

    private void submitFeedback(String endpointUrl, String jobId, String label, String notes) throws IOException, InterruptedException {
        String feedbackUrl = buildFeedbackUrl(endpointUrl);
        String payload = mapper.writeValueAsString(new FeedbackPayload(jobId, label, notes));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(feedbackUrl))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", "Burp-AI-Bridge/0.2.0")
                .timeout(SUBMIT_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge feedback returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
    }

    private AnalysisJobStatus getJobStatus(String statusUrl) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(statusUrl))
                .header("Accept", "application/json")
                .header("User-Agent", "Burp-AI-Bridge/0.2.0")
                .timeout(STATUS_TIMEOUT)
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge job status returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
        try {
            return mapper.readValue(response.body(), AnalysisJobStatus.class);
        } catch (IOException exception) {
            throw new IOException(
                    "Bridge job status returned HTTP 200 but the response could not be parsed: " + truncate(response.body()),
                    exception
            );
        }
    }

    public KaliToolInventoryResponse fetchToolInventory(String endpointUrl, boolean refresh) throws IOException, InterruptedException {
        String inventoryUrl = buildToolsInventoryUrl(normalizeEndpoint(endpointUrl), refresh);
        HttpResponse<String> response = sendGetWithRetry(inventoryUrl);
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge tool inventory returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
        try {
            return mapper.readValue(response.body(), KaliToolInventoryResponse.class);
        } catch (IOException exception) {
            throw new IOException(
                    "Bridge tool inventory returned HTTP 200 but the response could not be parsed: " + truncate(response.body()),
                    exception
            );
        }
    }

    public boolean checkRuntimeHealth(String endpointUrl) throws IOException, InterruptedException {
        String healthUrl = buildRuntimeHealthUrl(normalizeEndpoint(endpointUrl));
        HttpResponse<String> response = sendGetWithRetry(healthUrl);
        return response.statusCode() >= 200 && response.statusCode() < 300;
    }

    public List<BCheckCatalogEntry> fetchBcheckCatalog(String endpointUrl) throws IOException, InterruptedException {
        String catalogUrl = buildBcheckCatalogUrl(normalizeEndpoint(endpointUrl));
        HttpResponse<String> response = sendGetWithRetry(catalogUrl);
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge BCheck catalog returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
        try {
            return mapper.readValue(response.body(), new TypeReference<List<BCheckCatalogEntry>>() {
            });
        } catch (IOException exception) {
            throw new IOException(
                    "Bridge BCheck catalog returned HTTP 200 but the response could not be parsed: " + truncate(response.body()),
                    exception
            );
        }
    }

    public BCheckContentResponse fetchBcheckContent(String endpointUrl, String relativePath) throws IOException, InterruptedException {
        String contentUrl = buildBcheckContentUrl(normalizeEndpoint(endpointUrl), relativePath);
        HttpResponse<String> response = sendGetWithRetry(contentUrl);
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge BCheck content returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
        try {
            return mapper.readValue(response.body(), BCheckContentResponse.class);
        } catch (IOException exception) {
            throw new IOException(
                    "Bridge BCheck content returned HTTP 200 but the response could not be parsed: " + truncate(response.body()),
                    exception
            );
        }
    }

    public PreparedBurpExportResponse prepareBurpExport(String endpointUrl, AssessmentRequest payload) throws IOException, InterruptedException {
        String prepareUrl = buildBurpPrepareExportUrl(normalizeEndpoint(endpointUrl));
        String jsonPayload = mapper.writeValueAsString(payload);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(prepareUrl))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", "Burp-AI-Bridge/0.2.0")
                .timeout(SUBMIT_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge export preparation returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
        try {
            return mapper.readValue(response.body(), PreparedBurpExportResponse.class);
        } catch (IOException exception) {
            throw new IOException(
                    "Bridge export preparation returned HTTP 200 but the response could not be parsed: " + truncate(response.body()),
                    exception
            );
        }
    }

    public PhaseHistoryResponse fetchPhaseHistory(String endpointUrl, String jobId, String phase, int limit) throws IOException, InterruptedException {
        String historyUrl = buildPhaseHistoryUrl(normalizeEndpoint(endpointUrl), jobId, phase, limit);
        HttpResponse<String> response = sendGetWithRetry(historyUrl);
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge phase history returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
        try {
            return mapper.readValue(response.body(), PhaseHistoryResponse.class);
        } catch (IOException exception) {
            throw new IOException(
                    "Bridge phase history returned HTTP 200 but the response could not be parsed: " + truncate(response.body()),
                    exception
            );
        }
    }

    public AnalysisReasoningResponse fetchReasoningSummary(String endpointUrl, String jobId) throws IOException, InterruptedException {
        String reasoningUrl = buildReasoningUrl(normalizeEndpoint(endpointUrl), jobId);
        HttpResponse<String> response = sendGetWithRetry(reasoningUrl);
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Bridge reasoning summary returned HTTP " + response.statusCode() + ": " + truncate(response.body()));
        }
        try {
            return mapper.readValue(response.body(), AnalysisReasoningResponse.class);
        } catch (IOException exception) {
            throw new IOException(
                    "Bridge reasoning summary returned HTTP 200 but the response could not be parsed: " + truncate(response.body()),
                    exception
            );
        }
    }

    private void notifyProgress(Consumer<AnalysisJobStatus> progressCallback, AnalysisJobStatus status) {
        if (progressCallback != null && status != null) {
            progressCallback.accept(status);
        }
    }

    private AnalysisJobStatus toStatus(AnalysisJobAccepted accepted) {
        AnalysisJobStatus status = new AnalysisJobStatus();
        status.setJobId(accepted.getJobId());
        status.setStatus(accepted.getStatus());
        status.setStatusMessage(accepted.getStatusMessage());
        status.setEstimatedDuration(accepted.getEstimatedDuration());
        status.setComplexity(accepted.getComplexity());
        status.setRecommendation(accepted.getRecommendation());
        return status;
    }

    private String normalizeEndpoint(String endpointUrl) {
        if (endpointUrl == null || endpointUrl.isBlank()) {
            throw new IllegalArgumentException("The AI Bridge endpoint is blank.");
        }
        return endpointUrl.trim();
    }

    private String buildJobsUrl(String endpointUrl) {
        if (endpointUrl.endsWith("/jobs")) {
            return endpointUrl;
        }
        return endpointUrl.endsWith("/") ? endpointUrl + "jobs" : endpointUrl + "/jobs";
    }

    private String buildJobStatusUrl(String endpointUrl, String jobId) {
        return buildJobsUrl(endpointUrl) + "/" + jobId;
    }

    private String buildFeedbackUrl(String endpointUrl) {
        if (endpointUrl.endsWith("/api/analyze")) {
            return endpointUrl.substring(0, endpointUrl.length() - "/api/analyze".length()) + "/api/history/feedback";
        }
        if (endpointUrl.contains("/api/analyze/")) {
            return endpointUrl.replace("/api/analyze/", "/api/history/feedback/");
        }
        if (endpointUrl.endsWith("/analyze")) {
            return endpointUrl.substring(0, endpointUrl.length() - "/analyze".length()) + "/history/feedback";
        }
        return endpointUrl.endsWith("/") ? endpointUrl + "history/feedback" : endpointUrl + "/history/feedback";
    }

    private String buildToolsInventoryUrl(String endpointUrl, boolean refresh) {
        String base = trimAnalyzeSuffix(endpointUrl);
        String url = base.endsWith("/") ? base + "api/tools/inventory" : base + "/api/tools/inventory";
        if (refresh) {
            url += "?refresh=true";
        }
        return url;
    }

    private String buildRuntimeHealthUrl(String endpointUrl) {
        String base = trimAnalyzeSuffix(endpointUrl);
        return base.endsWith("/") ? base + "api/runtime/health" : base + "/api/runtime/health";
    }

    private String buildBcheckCatalogUrl(String endpointUrl) {
        String base = trimAnalyzeSuffix(endpointUrl);
        return base.endsWith("/") ? base + "api/bchecks/catalog?limit=250" : base + "/api/bchecks/catalog?limit=250";
    }

    private String buildBcheckContentUrl(String endpointUrl, String relativePath) {
        String base = trimAnalyzeSuffix(endpointUrl);
        String encodedPath = URLEncoder.encode(relativePath == null ? "" : relativePath, StandardCharsets.UTF_8);
        return base.endsWith("/") ? base + "api/bchecks/content?relative_path=" + encodedPath : base + "/api/bchecks/content?relative_path=" + encodedPath;
    }

    private String buildBurpPrepareExportUrl(String endpointUrl) {
        String base = trimAnalyzeSuffix(endpointUrl);
        return base.endsWith("/") ? base + "api/burp/prepare-export" : base + "/api/burp/prepare-export";
    }

    private String buildPhaseHistoryUrl(String endpointUrl, String jobId, String phase, int limit) {
        String base = trimAnalyzeSuffix(endpointUrl);
        String encodedJobId = URLEncoder.encode(jobId == null ? "" : jobId, StandardCharsets.UTF_8);
        String encodedPhase = URLEncoder.encode(phase == null ? "" : phase, StandardCharsets.UTF_8);
        String url = base.endsWith("/")
                ? base + "api/history/jobs/" + encodedJobId + "/phases?limit=" + Math.max(1, limit)
                : base + "/api/history/jobs/" + encodedJobId + "/phases?limit=" + Math.max(1, limit);
        if (!encodedPhase.isBlank()) {
            url += "&phase=" + encodedPhase;
        }
        return url;
    }

    private String buildReasoningUrl(String endpointUrl, String jobId) {
        String base = trimAnalyzeSuffix(endpointUrl);
        String encodedJobId = URLEncoder.encode(jobId == null ? "" : jobId, StandardCharsets.UTF_8);
        return base.endsWith("/") ? base + "api/history/jobs/" + encodedJobId + "/reasoning" : base + "/api/history/jobs/" + encodedJobId + "/reasoning";
    }

    private String trimAnalyzeSuffix(String endpointUrl) {
        String base = endpointUrl;
        if (base.endsWith("/api/analyze")) {
            return base.substring(0, base.length() - "/api/analyze".length());
        }
        if (base.endsWith("/api/analyze/")) {
            return base.substring(0, base.length() - "/api/analyze/".length());
        }
        return base;
    }

    private HttpResponse<String> sendGetWithRetry(String url) throws IOException, InterruptedException {
        IOException firstFailure = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .header("User-Agent", "Burp-AI-Bridge/0.2.0")
                    .timeout(STATUS_TIMEOUT)
                    .GET()
                    .build();
            try {
                return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (IOException exception) {
                if (attempt == 0 && isRetryableChannelFailure(exception)) {
                    firstFailure = exception;
                    continue;
                }
                throw exception;
            }
        }
        throw firstFailure == null ? new IOException("HTTP GET request failed.") : firstFailure;
    }

    private boolean isRetryableChannelFailure(IOException exception) {
        Throwable cursor = exception;
        while (cursor != null) {
            if (cursor instanceof ClosedChannelException) {
                return true;
            }
            String message = cursor.getMessage();
            if (message != null && message.toLowerCase().contains("closedchannel")) {
                return true;
            }
            cursor = cursor.getCause();
        }
        return false;
    }

    private String truncate(String body) {
        if (body == null || body.isBlank()) {
            return "<empty response body>";
        }
        return body.length() <= 500 ? body : body.substring(0, 500) + "...";
    }

    private record FeedbackPayload(String job_id, String label, String notes) {
    }
}
