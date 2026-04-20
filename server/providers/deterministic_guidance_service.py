from server.bapp_adapters import normalize_loaded_burp_tools
from server.bcheck_catalog import query_bchecks
from server.core.reference_enrichment_service import curated_references_for_class
from server.knowledge_base import search_notes_detailed
from server.local_guidance_db import query_guidance_packs

UNSAFE_PAYLOAD_MARKERS = (
    "<script",
    "javascript:",
    "file://",
    "127.0.0.1",
    "localhost",
    "169.254.169.254",
    "/etc/passwd",
    "whoami",
    "sleep(",
    "union select",
    "xp_cmdshell",
)


def numeric_neighbor_payloads(sample: str) -> list[str]:
    if not sample or not sample.isdigit():
        return []
    base_value = int(sample)
    values = [base_value, max(0, base_value - 1), base_value + 1, base_value + 2]
    deduped = []
    for value in values:
        text = str(value)
        if text not in deduped:
            deduped.append(text)
    return deduped


def payload_examples_for_class(vuln_class: str, sample: str) -> list[str]:
    if vuln_class == "access-control":
        return sanitize_payload_examples(numeric_neighbor_payloads(sample) or [
            "<same-format id from a second approved account>",
            "<same-format id from an adjacent record>",
            "<same object path with one permitted ownership change>",
        ])
    if vuln_class == "authentication":
        return sanitize_payload_examples(["<missing Authorization>", "<expired token>", "<lower-privilege token>", "<same session after logout>"])
    if vuln_class == "business-logic":
        return sanitize_payload_examples(["<baseline request replayed twice>", "<skip one prior step>", "<quantity +1>", "<repeat one allowed action>"])
    if vuln_class == "cache":
        return sanitize_payload_examples(["Cache-Control: no-cache", "Pragma: no-cache", "Accept-Encoding: identity", "<authenticated vs unauthenticated>"])
    if vuln_class == "cors":
        return sanitize_payload_examples(["https://example.com", "https://sub.example.com", "null", "http://example.com"])
    if vuln_class == "csrf":
        return sanitize_payload_examples(["<baseline token>", "<token removed>", "<token changed>", "Origin: https://example.com", "Referer: https://example.com/"])
    if vuln_class == "crypto-failures":
        return sanitize_payload_examples(["http://", "<missing Secure cookie>", "<missing HSTS>", "<exposed key material marker>"])
    if vuln_class == "deserialization":
        return sanitize_payload_examples(["<baseline serialized blob>", "<same blob with one harmless field change>", "<alternate type marker>", "<opaque token replay>"])
    if vuln_class == "file-upload":
        return sanitize_payload_examples(["proof.txt", "proof.TXT", "proof.svg", "image/svg+xml", "text/plain"])
    if vuln_class == "graphql":
        return sanitize_payload_examples(["query {__typename}", "query {viewer{__typename}}", "{\"query\":\"query {__typename}\"}", "{\"variables\":{}}"])
    if vuln_class == "http-request-smuggling":
        return sanitize_payload_examples(["Transfer-Encoding: chunked", "Content-Length: <baseline>", "<baseline body>", "<connection reuse observation>"])
    if vuln_class == "information-disclosure":
        return sanitize_payload_examples(["<missing required field>", "<wrong type>", "<unexpected method>", "<long benign marker>"])
    if vuln_class == "input-validation":
        return sanitize_payload_examples(["probe123", "\"probe123\"", "'probe123'", "<probe123>", "probe123-test"])
    if vuln_class == "insecure-design":
        return sanitize_payload_examples(["<repeat same action>", "<skip prior step>", "<reorder workflow>", "<quantity or amount +1>"])
    if vuln_class == "jwt-token":
        return sanitize_payload_examples(["<current token>", "<expired token>", "<lower-privilege token>", "<missing Authorization>"])
    if vuln_class == "mass-assignment":
        return sanitize_payload_examples(["\"role\":\"viewer\"", "\"permissions\":[\"read\"]", "\"status\":\"pending\"", "\"profile\":{\"timezone\":\"UTC\"}"])
    if vuln_class == "open-redirect":
        return sanitize_payload_examples(["https://example.com/", "//example.com/", "/relative/path", "https://example.com/%2e%2e"])
    if vuln_class == "path-traversal":
        return sanitize_payload_examples(["../public.txt", "..\\public.txt", "%2e%2e/public.txt", "safe/../public.txt"])
    if vuln_class == "race-condition":
        return sanitize_payload_examples(["<same approved request in two tabs>", "<same transfer twice>", "<redeem action replay>", "<parallel checkout submit>"])
    if vuln_class == "security-misconfiguration":
        return sanitize_payload_examples(["<same HTML route>", "<unauthenticated equivalent>", "<authenticated equivalent>", "<static asset path>"])
    if vuln_class == "secret-exposure":
        return sanitize_payload_examples(["<baseline response>", "<debug or verbose mode response>", "<config-like endpoint>", "<error response with stack trace>"])
    if vuln_class == "session-management":
        return sanitize_payload_examples(["<no cookie>", "<pre-login cookie>", "<post-login cookie>", "<post-logout cookie>"])
    if vuln_class == "sqli":
        return sanitize_payload_examples(["1", "0", "-1", "999999", "1.0"])
    if vuln_class == "ssti":
        return sanitize_payload_examples(["probe-template", "{{SAFE_PROBE}}", "${SAFE_PROBE}", "<%= SAFE_PROBE %>"])
    if vuln_class == "ssrf":
        return sanitize_payload_examples(["https://example.com/", "http://example.com/", "//example.com/", "/relative/path"])
    if vuln_class == "xss":
        return sanitize_payload_examples(["probe123", "\"probe123\"", "'probe123'", "<probe123>", "probe123-test"])
    if vuln_class == "xxe":
        return sanitize_payload_examples([
            "<baseline XML body>",
            "<same XML without DOCTYPE>",
            "<same XML with one harmless extra element>",
            "<same XML with internal entity only>",
        ])
    return sanitize_payload_examples(["<baseline value>", "<one benign structural variation>"])


def sanitize_payload_examples(payloads: list[str]) -> list[str]:
    deduped: list[str] = []
    for item in payloads:
        normalized = _sanitize_payload_example(item)
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped[:8]


def _sanitize_payload_example(item: str) -> str:
    normalized = (item or "").strip()
    if not normalized:
        return ""
    lowered = normalized.lower()
    if any(marker in lowered for marker in UNSAFE_PAYLOAD_MARKERS):
        return "<benign confirmation variant>"
    return normalized


def format_payload_examples(payloads: list[str]) -> str:
    if not payloads:
        return "build a short custom list from the captured baseline value"
    return ", ".join(f"`{item}`" for item in payloads[:5])


def build_local_resource_hints(matched_recipes: list[dict]) -> list[str]:
    hints: list[str] = []
    seen_classes: set[str] = set()
    for recipe in matched_recipes[:4]:
        vuln_class = (recipe.get("vuln_class") or "general").strip().lower()
        if vuln_class in seen_classes:
            continue
        seen_classes.add(vuln_class)
        kb_hits = search_notes_detailed(f"{vuln_class} {recipe.get('title', '')}".strip(), top_k=2).get("hits", [])[:2]
        bchecks = query_bchecks(limit=2, vuln_class=vuln_class, search=recipe.get("title", ""))[:2]
        kb_titles = [item.get("title") or item.get("file") or "" for item in kb_hits if item.get("title") or item.get("file")]
        bcheck_titles = [item.get("name") or "" for item in bchecks if item.get("name")]
        segments = []
        if kb_titles:
            segments.append("KB: " + ", ".join(kb_titles))
        if bcheck_titles:
            segments.append("BChecks: " + ", ".join(bcheck_titles))
        reference_links = curated_references_for_class(vuln_class)
        if reference_links:
            academy_links = [link for link in reference_links if "portswigger.net" in link][:1]
            github_links = [link for link in reference_links if "github.com" in link][:1]
            refs = []
            if academy_links:
                refs.append("PortSwigger: " + academy_links[0])
            if github_links:
                refs.append("GitHub: " + github_links[0])
            if refs:
                segments.append("References: " + " | ".join(refs))
        guidance_hits = query_guidance_packs([vuln_class], styles=["methodology", "validation-impact", "workflow-payload"], top_k=2).get("hits", [])
        if guidance_hits:
            pack_names = [item.get("name", "") for item in guidance_hits if item.get("name")]
            if pack_names:
                segments.append("Guidance DB: " + ", ".join(pack_names[:2]))
        if segments:
            hints.append(f"[{vuln_class}] Local resources to refine the next confirmation ladder: " + " | ".join(segments))
    return hints[:6]


def payload_recommendations(features: dict, matched_recipes: list[dict], target_descriptor_for_class) -> list[str]:
    recommendations = []
    seen_classes = set()
    local_resource_hints = build_local_resource_hints(matched_recipes)
    local_hint_map = {item.split("]", 1)[0].strip("["): item for item in local_resource_hints if item.startswith("[")}

    for recipe in matched_recipes[:4]:
        vuln_class = (recipe.get("vuln_class") or "general").strip().lower()
        if vuln_class in seen_classes:
            continue
        seen_classes.add(vuln_class)
        target_label, target_location = target_descriptor_for_class(features, vuln_class)
        target_name = target_label.strip("`")
        target_sample = features.get("param_samples", {}).get(target_name, "")
        payload_examples = payload_examples_for_class(vuln_class, target_sample)
        sample_text = f" | Baseline sample: `{target_sample}`" if target_sample else ""
        local_hint = local_hint_map.get(vuln_class, "")
        if local_hint:
            local_hint = f" | {local_hint}"
        recommendations.append(
            f"[{vuln_class}] Target {target_label} in {target_location}{sample_text} | Safe confirmation ladder: {format_payload_examples(payload_examples)}{local_hint}"
        )

    if not recommendations:
        target_name = features["param_names"][0] if features["param_names"] else "request parameter"
        recommendations.append(
            f"[general] Start with one low-noise comparison list against `{target_name}`: `<baseline value>`, `<quoted baseline>`, `<slightly longer benign marker>`."
        )

    return recommendations[:8]


def build_primary_suggestion_steps(recipe: dict, features: dict, target_descriptor_for_class, intruder_deemphasized_classes: set[str]) -> list[str]:
    vuln_class = (recipe.get("vuln_class") or "general").strip().lower()
    title = recipe.get("title") or "Manual review"
    method = (features.get("method") or "GET").upper()
    target_label, target_location = target_descriptor_for_class(features, vuln_class)
    target_name = target_label.strip("`")
    target_sample = features.get("param_samples", {}).get(target_name, "")
    payloads = payload_examples_for_class(vuln_class, target_sample)
    payload_text = format_payload_examples(payloads)
    resource_hints = build_local_resource_hints([recipe])

    steps = [
        (
            f"Primary track [{vuln_class}] {title}: keep one untouched baseline {method} tab in Burp Repeater, then test the next approved variant against "
            f"{target_location} {target_label} while you compare status, headers, length, timing, and visible body deltas."
        )
    ]
    if vuln_class in intruder_deemphasized_classes:
        steps.append(f"Intruder note for [{vuln_class}]: stay in Repeater first and use this short confirmation ladder: {payload_text}.")
    else:
        steps.append(f"Intruder focus for [{vuln_class}]: after Repeater proves a delta, mark only the confirmed insertion point and start with this short confirmation ladder: {payload_text}.")
    if resource_hints:
        steps.append(resource_hints[0])
    if recipe.get("operator_questions"):
        steps.append(f"Resolve this before expanding the test: {recipe['operator_questions'][0]}")
    steps.append(f"AI follow-up for [{vuln_class}]: send back the exact delta so the next advisory can rank business impact without overselling it.")
    return steps[:5]


def build_impact_paths(matched_recipes: list[dict], bapp_summary: dict, impact_paths_by_class: dict) -> list[str]:
    items: list[str] = []
    seen_classes: set[str] = set()
    for recipe in matched_recipes[:6]:
        vuln_class = recipe.get("vuln_class", "general")
        if vuln_class in seen_classes:
            continue
        seen_classes.add(vuln_class)
        path = impact_paths_by_class.get(vuln_class)
        if path:
            items.append(f"[{vuln_class}] {path}")

    for vuln_class in bapp_summary.get("suggested_vuln_classes", []):
        if vuln_class in seen_classes:
            continue
        path = impact_paths_by_class.get(vuln_class)
        if path:
            seen_classes.add(vuln_class)
            items.append(f"[{vuln_class}] {path}")

    return items[:6]


def project_readiness(payload, matched_recipes: list[dict], preferred_burp_tools: list[str], bcheck_recommendations: list[str]) -> tuple[str, list[str]]:
    score = 0
    checks: list[str] = []

    scope_ready = bool((getattr(payload, "scope_includes_text", "") or "").strip()) or bool((getattr(payload, "target_url", "") or "").strip())
    if scope_ready:
        score += 15
        checks.append("[ready] Scope anchor: target and in-scope guidance are present for this advisory.")
    else:
        checks.append("[needs] Scope anchor: add an in-scope URL or explicit target before broader testing.")

    exclusions_ready = bool((getattr(payload, "scope_excludes_text", "") or "").strip()) or bool((getattr(payload, "saved_program_policy_text", "") or "").strip())
    if exclusions_ready:
        score += 10
        checks.append("[ready] Program boundaries: out-of-scope or project policy notes are present.")
    else:
        checks.append("[needs] Program boundaries: add out-of-scope targets or saved program rules so the workflow stays bounty-safe.")

    rate_ready = bool((getattr(payload, "rate_limit_text", "") or "").strip()) or bool((getattr(payload, "max_concurrency_text", "") or "").strip())
    if rate_ready:
        score += 10
        checks.append("[ready] Rate limits: concurrency or pacing rules are captured for safe scanner and Intruder use.")
    else:
        checks.append("[needs] Rate limits: capture concurrency or pacing rules before broader scan expansion.")

    headers_ready = bool((getattr(payload, "custom_headers_text", "") or "").strip())
    if headers_ready:
        score += 10
        checks.append("[ready] Required headers: custom bug-bounty or auth headers are present for consistent requests.")
    else:
        checks.append("[needs] Required headers: add any bug-bounty, auth, or researcher-identification headers if the program requires them.")

    baseline_ready = bool((getattr(payload, "burp_config_export_text", "") or "").strip()) or bool((getattr(payload, "burp_screenshot_audit_text", "") or "").strip())
    if baseline_ready:
        score += 15
        checks.append("[ready] Burp baseline: config export or Burp settings screenshots were saved for global-settings guidance.")
    else:
        checks.append("[needs] Burp baseline: save a Burp config export or settings screenshots in AI-Bridge Settings.")

    loaded_tools_ready = bool((getattr(payload, "loaded_burp_tools_text", "") or "").strip())
    if loaded_tools_ready:
        score += 10
        checks.append("[ready] Loaded tools: AI Bridge knows which Burp tools and BApps are already available.")
    else:
        checks.append("[needs] Loaded tools: list the Burp tools and BApps already installed so AI Bridge can prefer them first.")

    evidence_ready = any([
        bool((getattr(payload, "logger_evidence_text", "") or "").strip()),
        bool((getattr(payload, "bapp_findings_text", "") or "").strip()),
        bool((getattr(payload, "tool_results_text", "") or "").strip()),
        bool(getattr(payload, "evidence_timeline_entries", None)),
    ])
    if evidence_ready:
        score += 10
        checks.append("[ready] Evidence capture: Logger++, BApp, tool-output, or evidence-timeline material is available for correlation.")
    else:
        checks.append("[needs] Evidence capture: add Logger++, tool-output, or evidence-timeline notes so the next action is driven by real deltas.")

    if bcheck_recommendations:
        score += 10
        checks.append("[ready] BChecks: matching checks were identified for this hypothesis.")
    else:
        checks.append("[optional] BChecks: no matching BChecks were identified yet, so confirmation will stay manual for now.")

    callback_classes = {"ssrf", "xxe"}
    needs_callback = any((recipe.get("vuln_class") or "").strip().lower() in callback_classes for recipe in matched_recipes[:4])
    callback_ready = bool((getattr(payload, "collaborator_evidence_text", "") or "").strip())
    if needs_callback and callback_ready:
        score += 10
        checks.append("[ready] Callback visibility: Collaborator evidence or sync context exists for callback-oriented testing.")
    elif needs_callback:
        checks.append("[needs] Callback visibility: verify Collaborator readiness before testing SSRF or XXE impact branches.")
    else:
        score += 10
        checks.append("[optional] Callback visibility: not required for the current top hypothesis.")

    score = max(0, min(score, 100))
    blockers = sum(1 for item in checks if item.startswith("[needs]"))
    if score >= 85:
        state = "ready for impact-oriented testing"
    elif score >= 65:
        state = "ready for confirmation, but tighten the blockers before broader scans"
    else:
        state = "not ready for broad scanning yet"
    summary = f"{score}/100 - {state}."
    if blockers:
        summary += f" {blockers} blocker(s) still need operator attention."
    if preferred_burp_tools:
        summary += " Preferred Burp tools: " + ", ".join(item.split(':', 1)[0] for item in preferred_burp_tools[:3]) + "."
    return summary, checks[:8]


def build_burp_action_checklist(
    payload,
    matched_recipes: list[dict],
    preferred_burp_tools: list[str],
    bcheck_recommendations: list[str],
    readiness_summary: str,
    intruder_deemphasized_classes: set[str],
) -> list[str]:
    checklist: list[str] = [f"[Project Prep] Readiness check: {readiness_summary}"]
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()

    if (getattr(payload, "scope_includes_text", "") or "").strip() or (getattr(payload, "scope_excludes_text", "") or "").strip():
        checklist.append("[Project Prep] Confirm Burp scope matches the saved in-scope and out-of-scope target list before launching any scan.")
    if (getattr(payload, "custom_headers_text", "") or "").strip():
        checklist.append("[Settings] Verify required bug-bounty or auth headers are applied through Burp settings or AI Bridge-managed rules.")
    if (getattr(payload, "rate_limit_text", "") or "").strip() or (getattr(payload, "max_concurrency_text", "") or "").strip():
        checklist.append("[Settings] Set or select a Burp Resource Pool that matches the saved concurrency and pacing limits.")

    top_class = (matched_recipes[0].get("vuln_class") if matched_recipes else "general") or "general"
    if "intruder" in source_tool:
        checklist.append("[Intruder] Stay in Intruder for the next move, keep positions narrow, and use the smallest custom payload set that still tests the hypothesis.")
        checklist.append("[Baseline] Keep one untouched request or baseline response available for comparison while Intruder runs.")
    else:
        checklist.append("[Repeater] Keep one untouched baseline tab and change one field, header, or body fragment at a time before widening the test.")

    if top_class in intruder_deemphasized_classes:
        checklist.append(f"[Intruder] Hold Intruder until Repeater confirms the [{top_class}] hypothesis with a stable delta.")
    else:
        checklist.append(f"[Intruder] After Repeater shows a delta, mark only the confirmed insertion point for [{top_class}] and start with a very short payload list.")

    if preferred_burp_tools:
        for item in preferred_burp_tools[:3]:
            checklist.append("[Burp Tool] " + item)

    if (getattr(payload, "logger_evidence_text", "") or "").strip() or any("Logger++" in item for item in preferred_burp_tools):
        checklist.append("[Logger++] Save the baseline request, confirming delta, and strongest impact request with comments or filters before reporting.")

    if bcheck_recommendations:
        checklist.append("[BChecks] Import or verify the closest recommended BChecks before trusting a scanner-only conclusion.")

    if any((recipe.get("vuln_class") or "").strip().lower() in {"ssrf", "xxe"} for recipe in matched_recipes[:4]):
        checklist.append("[Collaborator] Verify Collaborator visibility before testing callback-oriented impact paths.")

    checklist.append("[Reporting] Preserve the baseline request, changed request, key delta, and strongest impact evidence as separate artifacts.")
    return checklist[:10]


def loaded_burp_helpers(payload, matched_recipes: list[dict], bapp_summary: dict, helper_priorities: dict, tool_usage_notes: dict) -> tuple[dict, list[str]]:
    loaded = normalize_loaded_burp_tools(getattr(payload, "loaded_burp_tools_text", "") or "")
    detected_tools = loaded.get("detected_tools", [])
    logger_evidence = (getattr(payload, "logger_evidence_text", "") or "").strip()
    if not detected_tools and not logger_evidence:
        return loaded, []

    preferred: list[str] = []
    seen: set[str] = set()
    seen_classes: list[str] = []
    for recipe in matched_recipes[:4]:
        vuln_class = (recipe.get("vuln_class") or "").strip().lower()
        if vuln_class and vuln_class not in seen_classes:
            seen_classes.append(vuln_class)
    for vuln_class in bapp_summary.get("suggested_vuln_classes", []):
        if vuln_class not in seen_classes:
            seen_classes.append(vuln_class)

    if logger_evidence:
        seen.add("Logger++ evidence")
        preferred.append("Logger++ evidence: treat the pasted status, length, header, and timing deltas as stronger evidence than generic operator notes.")

    for vuln_class in seen_classes:
        for tool_name in helper_priorities.get(vuln_class, []):
            if tool_name not in detected_tools or tool_name in seen:
                continue
            seen.add(tool_name)
            preferred.append(f"{tool_name}: {tool_usage_notes[tool_name]}")

    for line in loaded.get("recommendation_lines", []):
        tool_name = line.split(":", 1)[0].strip()
        if tool_name in seen:
            continue
        seen.add(tool_name)
        preferred.append(line)

    return loaded, preferred[:4]


def best_burp_helper_label(preferred_burp_tools: list[str]) -> str:
    if not preferred_burp_tools:
        return "Repeater, then Logger/Comparer if the diff is noisy."
    return preferred_burp_tools[0].split(":", 1)[0].strip()


def build_burp_settings_recommendations(
    payload,
    matched_recipes: list[dict],
    bcheck_recommendations: list[str],
    loaded_burp_tools: dict,
    preferred_burp_tools: list[str],
) -> list[str]:
    recommendations: list[str] = []
    scope_includes = (getattr(payload, "scope_includes_text", "") or "").strip()
    scope_excludes = (getattr(payload, "scope_excludes_text", "") or "").strip()
    rate_limit = (getattr(payload, "rate_limit_text", "") or "").strip()
    concurrency = (getattr(payload, "max_concurrency_text", "") or "").strip()
    custom_headers = (getattr(payload, "custom_headers_text", "") or "").strip()

    if scope_includes or scope_excludes:
        recommendations.append("Project > Scope: mirror the AI Bridge in-scope and out-of-scope target list here so Burp tools, scanner tasks, and manual tests stay aligned with the program boundary.")
    if custom_headers:
        recommendations.append("Tools > Proxy > Match and replace: add the approved bug-bounty or researcher identification header once at project level so Scanner, Repeater, and Intruder stay consistent.")
    if rate_limit or concurrency:
        recommendations.append("New Scan > Resource pool: create or select a dedicated pool that matches the program's concurrency and delay rules before launching broader scans or Intruder attacks.")
    if preferred_burp_tools:
        recommendations.append("Loaded Burp helpers: start with " + "; ".join(preferred_burp_tools[:3]))
    recommendations.append("Configuration library: duplicate the closest built-in crawl/audit configuration and tune it for this hypothesis instead of editing every scan from scratch.")
    recommendations.append("Project > Logging or Logger: keep request and response evidence for the baseline request, the confirming delta, and the strongest impact example so the report is easy to support.")

    seen_classes: set[str] = set()
    for recipe in matched_recipes[:4]:
        vuln_class = recipe.get("vuln_class", "general")
        if vuln_class in seen_classes:
            continue
        seen_classes.add(vuln_class)
        if vuln_class in {"access-control", "authentication", "jwt-token", "session-management"}:
            recommendations.append("Project > Sessions: verify the project session-handling approach before testing auth or access-control findings so Burp preserves the right authenticated context.")
        elif vuln_class in {"ssrf", "xxe"}:
            recommendations.append("Project > Collaborator: if the program allows callback-style evidence, verify Collaborator visibility and logging before testing outbound-request hypotheses.")
        elif vuln_class in {"race-condition", "business-logic"}:
            recommendations.append("Resource pool and manual tabs: keep rate control conservative and use Burp history plus evidence logging to compare duplicate or reordered requests safely.")
        elif vuln_class in {"sqli", "ssti", "command-injection", "path-traversal"}:
            recommendations.append("Configuration library or scan checks: prefer focused checks and narrow insertion-point coverage for high-risk server-side input issues before broader scanning.")
        elif vuln_class in {"xss", "csrf", "cors"}:
            recommendations.append("Tools > Proxy and browser-linked workflows: keep headers, cookies, and browser context stable so Burp comparisons reflect real browser-state behavior.")

    if bcheck_recommendations:
        recommendations.append("BChecks: verify the closest recommended BChecks are imported and enabled before relying on the scan result. Treat them as supporting evidence, not the only confirmation.")
    if "Logger++" in loaded_burp_tools.get("detected_tools", []) or (getattr(payload, "logger_evidence_text", "") or "").strip():
        recommendations.append("Logger++: keep a filter or comment set for the baseline request, the confirming delta, and the strongest impact request so the evidence is already organized for reporting.")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in recommendations:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped[:8]
