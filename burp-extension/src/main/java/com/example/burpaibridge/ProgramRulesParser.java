package com.example.burpaibridge;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ProgramRulesParser {
    private static final Pattern HEADER_PATTERN = Pattern.compile("(?i)\\b([A-Za-z][A-Za-z0-9-]{1,60})\\s*:\\s*([^\\r\\n]+)");
    private static final Pattern CONCURRENCY_PATTERN = Pattern.compile(
            "(?i)(?:max(?:imum)?|only|limit(?:ed)?\\s+to|up\\s+to)?\\s*(\\d{1,3})\\s+(?:concurrent|parallel)\\s+(?:requests?|connections?|threads?)"
    );
    private static final Pattern RATE_PATTERN = Pattern.compile(
            "(?i)(\\d{1,4}(?:\\.\\d{1,2})?)\\s*(?:req(?:uests?)?|rps)\\s*/\\s*(?:s|sec|second)"
    );
    private static final Pattern DELAY_PATTERN = Pattern.compile(
            "(?i)(?:delay|wait|pause)\\s*(?:between\\s+requests?)?\\s*(?:of\\s*)?(\\d{1,6})\\s*(ms|milliseconds?|s|sec|seconds?|m|minutes?)"
    );
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s,]+");

    private ProgramRulesParser() {
    }

    public static ParsedProgramRules parse(String rawText) {
        if (rawText == null || rawText.isBlank()) {
            return ParsedProgramRules.empty();
        }

        String maxConcurrency = "";
        String rateLimit = "";
        Set<String> headers = new LinkedHashSet<>();
        Set<String> includes = new LinkedHashSet<>();
        Set<String> excludes = new LinkedHashSet<>();
        Set<String> notes = new LinkedHashSet<>();

        for (String rawLine : rawText.split("\\R")) {
            String line = normalizeLine(rawLine);
            if (line.isBlank()) {
                continue;
            }

            String lowered = line.toLowerCase(Locale.ROOT);

            if (maxConcurrency.isBlank()) {
                Matcher concurrencyMatcher = CONCURRENCY_PATTERN.matcher(line);
                if (concurrencyMatcher.find()) {
                    maxConcurrency = concurrencyMatcher.group(1);
                }
            }

            if (rateLimit.isBlank()) {
                Matcher rateMatcher = RATE_PATTERN.matcher(line);
                if (rateMatcher.find()) {
                    rateLimit = rateMatcher.group(1) + " req/s max";
                } else {
                    Matcher delayMatcher = DELAY_PATTERN.matcher(line);
                    if (delayMatcher.find()) {
                        rateLimit = delayMatcher.group(1) + " " + normalizeTimeUnit(delayMatcher.group(2)) + " delay between requests";
                    }
                }
            }

            Matcher headerMatcher = HEADER_PATTERN.matcher(line);
            while (headerMatcher.find()) {
                String name = headerMatcher.group(1).trim();
                String value = headerMatcher.group(2).trim();
                if (looksLikeHeader(name, value)) {
                    headers.add(name + ": " + value);
                }
            }

            boolean mentionsScope = lowered.contains("scope") || lowered.contains("in-scope") || lowered.contains("out-of-scope")
                    || lowered.contains("do not test") || lowered.contains("do not scan") || lowered.contains("exclude");
            Matcher urlMatcher = URL_PATTERN.matcher(line);
            List<String> urls = new ArrayList<>();
            while (urlMatcher.find()) {
                urls.add(urlMatcher.group());
            }
            if (!urls.isEmpty()) {
                if (lowered.contains("out-of-scope") || lowered.contains("exclude") || lowered.contains("do not test") || lowered.contains("do not scan")) {
                    excludes.addAll(urls);
                } else if (lowered.contains("in-scope") || mentionsScope) {
                    includes.addAll(urls);
                }
            }

            if (containsPolicySignal(lowered)) {
                notes.add(line);
            }
        }

        return new ParsedProgramRules(
                maxConcurrency,
                rateLimit,
                List.copyOf(headers),
                List.copyOf(includes),
                List.copyOf(excludes),
                List.copyOf(notes)
        );
    }

    private static String normalizeLine(String rawLine) {
        if (rawLine == null) {
            return "";
        }
        String value = rawLine.trim();
        while (value.startsWith("-") || value.startsWith("*") || value.startsWith("\u2022")) {
            value = value.substring(1).trim();
        }
        return value;
    }

    private static String normalizeTimeUnit(String unit) {
        String value = unit == null ? "" : unit.toLowerCase(Locale.ROOT);
        return switch (value) {
            case "ms", "millisecond", "milliseconds" -> "ms";
            case "s", "sec", "second", "seconds" -> "seconds";
            case "m", "minute", "minutes" -> "minutes";
            default -> value;
        };
    }

    private static boolean looksLikeHeader(String name, String value) {
        String loweredName = name.toLowerCase(Locale.ROOT);
        if (loweredName.equals("http") || loweredName.equals("https")) {
            return false;
        }
        return !value.isBlank() && !value.contains("://");
    }

    private static boolean containsPolicySignal(String lowered) {
        return lowered.contains("allowed")
                || lowered.contains("only")
                || lowered.contains("concurrent")
                || lowered.contains("rate")
                || lowered.contains("delay")
                || lowered.contains("header")
                || lowered.contains("hours")
                || lowered.contains("utc")
                || lowered.contains("business hour")
                || lowered.contains("time window")
                || lowered.contains("weekdays")
                || lowered.contains("out-of-scope")
                || lowered.contains("in-scope")
                || lowered.contains("do not")
                || lowered.contains("forbidden")
                || lowered.contains("authenticated")
                || lowered.contains("whitelist")
                || lowered.contains("allowlist");
    }

    public record ParsedProgramRules(
            String maxConcurrency,
            String rateLimit,
            List<String> customHeaders,
            List<String> inScopeUrls,
            List<String> outOfScopeUrls,
            List<String> notes
    ) {
        public static ParsedProgramRules empty() {
            return new ParsedProgramRules("", "", List.of(), List.of(), List.of(), List.of());
        }

        public boolean isEmpty() {
            return maxConcurrency.isBlank()
                    && rateLimit.isBlank()
                    && customHeaders.isEmpty()
                    && inScopeUrls.isEmpty()
                    && outOfScopeUrls.isEmpty()
                    && notes.isEmpty();
        }
    }
}
