import json
import base64
from pathlib import Path
import re
from urllib.parse import urlparse
from urllib.parse import unquote

import requests

from server.bapp_adapters import normalize_loaded_burp_tools
from server.collaborator_parser import summarize_collaborator_evidence
from server.core.runtime_model_override_service import get_active_ollama_model
from server.kali_tools import inventory_summary_text
from server.knowledge_base import search_notes_detailed
from server.memory_retrieval import (
    build_endpoint_fingerprint,
    describe_history_correlation,
    find_similar_history,
    summarize_similar_findings,
)
from server.privacy_utils import normalize_privacy_mode, sanitize_free_text, sanitize_http_message
from server.rule_engine import build_rule_context, summarize_http_message
from server.profiles import get_profile, normalize_profile_name
from server.settings import (
    OLLAMA_TIMEOUT_SECONDS,
    OLLAMA_URL,
    OLLAMA_VISION_MODEL,
    OLLAMA_VISION_TIMEOUT_SECONDS,
    PRIVACY_MODE,
    SKIP_MODEL_FOR_LOW_SIGNAL,
)
from server.review_dataset import query_review_examples

MAX_REQUEST_HEADER_LINES = 30
MAX_RESPONSE_HEADER_LINES = 40
MAX_REQUEST_BODY_PREVIEW_CHARS = 1200
MAX_RESPONSE_BODY_PREVIEW_CHARS = 2000
STATIC_ASSET_EXTENSIONS = {
    ".webmanifest", ".json", ".map", ".txt", ".xml", ".css", ".js",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
}
SCREENSHOT_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}
MAX_SCREENSHOT_IMAGES = 4
MAX_SCREENSHOT_FILE_BYTES = 8 * 1024 * 1024


def _format_list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "- <none>"


def _format_recipe_block(matched_recipes: list[dict]) -> str:
    if not matched_recipes:
        return "- <no matched recipes>"

    blocks = []
    for recipe in matched_recipes[:5]:
        evidence = "; ".join(recipe.get("evidence", [])) or "general request/response context"
        blocks.append(
            f"- {recipe['title']} [{recipe.get('severity', 'info')}]\n"
            f"  Summary: {recipe['summary']}\n"
            f"  Evidence: {evidence}\n"
            f"  Questions: {' | '.join(recipe.get('operator_questions', [])) or '<none>'}"
        )
    return "\n".join(blocks)


def _format_operator_answers(operator_answers: dict | None) -> str:
    if not operator_answers:
        return "- <no operator answers supplied>"

    lines = []
    for question, answer in operator_answers.items():
        normalized_question = (question or "").strip()
        normalized_answer = (answer or "").strip()
        if not normalized_answer:
            continue
        lines.append(f"- Q: {normalized_question}\n  A: {normalized_answer}")
    return "\n".join(lines) if lines else "- <no operator answers supplied>"


def _suggestion_follow_up_request(payload) -> str:
    operator_answers = getattr(payload, "operator_answers", None) or {}
    for question, answer in operator_answers.items():
        normalized_question = (question or "").strip().lower()
        normalized_answer = (answer or "").strip()
        if "suggestion" in normalized_question and normalized_answer:
            return normalized_answer
    return ""


def _follow_up_intents(request: str) -> dict[str, bool]:
    lowered = (request or "").lower()
    return {
        "steps": any(keyword in lowered for keyword in ("step", "steps", "sequence", "workflow", "burp", "repeater")),
        "intruder": any(keyword in lowered for keyword in ("intruder", "pitchfork", "cluster bomb", "battering ram")),
        "payloads": any(keyword in lowered for keyword in ("payload", "payloads", "seclist", "seclists", "wordlist")),
        "tools": any(keyword in lowered for keyword in ("kali", "tool", "tools", "command", "commands", "curl", "nuclei", "httpx", "ffuf")),
    }


def _follow_up_prompt_instructions(payload) -> str:
    request = _suggestion_follow_up_request(payload)
    if not request:
        return "- No explicit suggestion follow-up request was supplied."

    intents = _follow_up_intents(request)
    return "\n".join([
        f"- The operator explicitly asked: {request}",
        "- Treat that follow-up request as the primary task, not as a side note.",
        "- Answer with exact execution order, not generic advice.",
        "- Name the exact Burp tool to use first: Repeater, Intruder, or Comparer.",
        "- Name the exact insertion point, parameter, or header to edit first when you can infer it from the request plan.",
        "- If they ask for Burp Repeater guidance, return 4 to 8 numbered Repeater steps with baseline tab, duplicate tabs, concrete edits per tab, and what to compare after each send.",
        "- If they ask for Intruder guidance, return 4 to 8 numbered Intruder steps with attack type, positions, payload set order, grep or diff checks, and stop conditions.",
        "- If they ask for payloads, return 3 to 8 concrete payloads or header values in the order they should be tried.",
        "- Use SecLists only when it fits the hypothesis. If a short manual list is better, say that plainly.",
        "- If they ask which Kali tools to run, name the first tool and first command to run now, then the second command only if the first produces a useful delta.",
        f"- Intent flags: steps={intents['steps']}, intruder={intents['intruder']}, payloads={intents['payloads']}, tools={intents['tools']}.",
    ])


def _tool_help_summary(tool_help_text: str | None) -> str:
    text = (tool_help_text or "").strip()
    if not text:
        return "No tool help text supplied."
    compact = " ".join(text.split())
    return compact[:1000] + ("..." if len(compact) > 1000 else "")


def _scanner_issue_context(payload) -> str:
    annotations = [item.strip().lower() for item in (getattr(payload, "annotations", None) or []) if item]
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    dashboard_issue = getattr(payload, "burp_dashboard_issue", None) or {}
    related_issues = [
        item for item in (getattr(payload, "burp_related_scanner_issues", None) or [])
        if isinstance(item, dict)
    ]
    if "audit_issue_selected" in annotations or "scanner_auto_triage" in annotations or "audit-issue" in source_tool:
        combined_issue_text = " ".join([
            (getattr(payload, "bapp_findings_text", "") or ""),
            (getattr(payload, "tool_results_text", "") or ""),
        ]).lower()
        issue_specific = []
        if "xml external entity injection" in combined_issue_text or "xxe" in combined_issue_text:
            issue_specific.extend([
                "- Exact issue type observed: XML external entity injection (XXE).",
                "- Give the next steps against the XML request body itself: keep one untouched baseline, then compare XML without the DTD, then one harmless structural XML variation.",
                "- If you mention Intruder, focus on the XML body or entity-bearing portion only. Do not suggest broad parameter fuzzing first.",
                "- If you mention Burp or BChecks, prioritize XML or XXE checks and parser-behavior confirmation over generic discovery steps.",
            ])
        if "collaborator dns interaction" in combined_issue_text or "dns interaction" in combined_issue_text:
            issue_specific.extend([
                "- Burp also recorded Collaborator DNS interaction for this request, so treat the callback as supporting evidence rather than a separate unrelated finding.",
                "- Correlate the callback timing with the exact XML edit or payload variant that triggered it, and keep the next confirmation steps on the same request family.",
                "- Prefer follow-up steps that confirm impact or parser behavior without discarding the Burp-marked XXE hypothesis.",
            ])
        if isinstance(dashboard_issue, dict) and dashboard_issue:
            issue_name = (dashboard_issue.get("name") or dashboard_issue.get("title") or dashboard_issue.get("issue_name") or "").strip()
            issue_detail = (dashboard_issue.get("detail") or dashboard_issue.get("issue_detail") or "").strip()
            issue_url = (dashboard_issue.get("url") or dashboard_issue.get("target_url") or getattr(payload, "target_url", "") or "").strip()
            highlight_items = [
                item for item in (dashboard_issue.get("highlights") or [])
                if isinstance(item, dict)
            ]
            highlight_text = ""
            for item in highlight_items:
                candidate = (item.get("text") or "").strip()
                if candidate:
                    highlight_text = candidate
                    break
            if issue_name:
                issue_specific.append(f"- Selected Burp Scanner issue anchor: {issue_name}.")
            if issue_url:
                issue_specific.append(f"- Keep the case anchored to this exact request family first: {issue_url}.")
            if issue_detail:
                issue_specific.append(f"- Selected issue detail: {issue_detail[:220]}")
            if highlight_text:
                issue_specific.append(f"- Burp highlighted this likely sink or evidence excerpt: {highlight_text[:180]}")
            issue_specific.extend([
                "- Do not switch the primary vulnerability family away from the selected Burp Scanner issue unless the attached evidence clearly contradicts it.",
                "- Treat related issues as supporting context only. They may suggest the next bounded escalation branch, but they do not replace the selected scanner issue as the anchor.",
            ])
        if related_issues:
            related_lines = []
            for item in related_issues[:4]:
                name = (item.get("name") or item.get("title") or "related issue").strip()
                severity = (item.get("severity") or "info").strip()
                detail = (item.get("detail") or "").strip()
                related_lines.append(
                    f"- Related Burp Scanner issue already present on the same target: {name} [{severity}]"
                    + (f" - {detail[:140]}" if detail else "")
                )
            issue_specific.extend([
                "- Treat the selected Burp Scanner issue as the anchor hypothesis, but also use the related Burp Scanner issues below to look for safe combined escalation paths on the same request family.",
                "- Only join findings when the same request, object, workflow, or trust boundary ties them together. Do not invent multi-bug chains with no shared evidence.",
                "- Prefer guidance that first confirms the scanner-marked issue in Repeater, then tests one bounded escalation branch suggested by the related issue set.",
                *related_lines,
            ])
        return "\n".join([
            "- The payload came from Burp Scanner issue context rather than raw traffic alone.",
            "- The full anchor request was forwarded with the Burp issue summary, so use that exact request as the baseline rather than reconstructing it from prose.",
            "- Treat the Burp finding as primary evidence that must be confirmed or narrowed, not rediscovered from scratch.",
            "- Start by deciding whether the selected Burp issue looks likely real or likely false positive from the highlighted sink, object boundary, or attached issue detail.",
            "- If the issue looks likely real, move directly from one bounded confirmation step into the strongest in-scope impact-evidence path on the same issue family.",
            "- Prefer exact confirmation steps in Burp Repeater first, then one minimal Intruder or Kali WSL branch only if needed.",
            "- Prefer local Burp starter assets, matched BChecks, KB hints, guidance packs, and review examples before broader expansion.",
            "- Use reference links for methodology only. Do not suggest internet exploit searches or exploit chains.",
            "- If upstream BChecks are suggested, explain whether to enable them before broader manual testing.",
            *issue_specific,
        ])
    return "- No Burp Scanner issue context was supplied."


def _burp_origin_context(payload) -> str:
    annotations = {item.strip().lower() for item in (getattr(payload, "annotations", None) or []) if item}
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    lines: list[str] = []

    if "tool_repeater" in annotations or "repeater_context" in annotations or "repeater" in source_tool:
        lines.extend([
            "- The request was sent from Burp Repeater context.",
            "- Prefer the next 4 to 8 steps as concrete Repeater actions with a baseline tab, one change per duplicate tab, and explicit compare points after each send.",
            "- Do not default to broad fuzzing if one or two focused Repeater confirmations would narrow the issue first.",
            "- Keep Intruder advice secondary unless the Repeater delta is already strong enough to justify expansion.",
        ])

    if "tool_intruder" in annotations or "intruder_context" in annotations or "intruder" in source_tool:
        lines.extend([
            "- The request was sent from Burp Intruder context.",
            "- If Intruder is appropriate, specify the exact attack type, payload positions, payload order, and the first shortlist to try before mentioning larger wordlists.",
            "- Default to Intruder-specific guidance first, and mention Repeater only as a baseline or confirmation aid when necessary.",
        ])

    if "tool_scanner" in annotations or "scanner_context" in annotations or "scanner_results_context" in annotations:
        lines.extend([
            "- The request came from Burp Scanner or Dashboard issue context.",
            "- Treat the Burp finding as prior evidence that should be confirmed, narrowed, or disproved, not rediscovered from scratch.",
        ])

    if "request_editor_context" in annotations:
        lines.append("- The operator invoked AI Bridge from a request editor, so focus on request-side edits first.")
    if "response_view_context" in annotations:
        lines.append("- The operator invoked AI Bridge from a response view, so reference concrete response deltas to compare on the next step.")

    return "\n".join(lines) if lines else "- No explicit Burp tool-origin context was supplied."


def _format_program_context(payload) -> str:
    items = [
        ("In-scope URLs", getattr(payload, "scope_includes_text", "") or ""),
        ("Out-of-scope URLs", getattr(payload, "scope_excludes_text", "") or ""),
        ("Rate limit", getattr(payload, "rate_limit_text", "") or ""),
        ("Max concurrency", getattr(payload, "max_concurrency_text", "") or ""),
        ("Custom headers", getattr(payload, "custom_headers_text", "") or ""),
        ("Program policy notes", getattr(payload, "program_policy_text", "") or ""),
        ("Saved project policy notes", getattr(payload, "saved_program_policy_text", "") or ""),
    ]

    lines = []
    for label, value in items:
        normalized = value.strip()
        if normalized:
            lines.append(f"- {label}: {normalized}")
    return "\n".join(lines) if lines else "- <no program context supplied>"


def _tool_results_summary(tool_results_text: str | None) -> str:
    text = (tool_results_text or "").strip()
    if not text:
        return "No manual tool results supplied."
    compact = text[:2000]
    return compact + ("..." if len(text) > 2000 else "")


def _burp_config_export_summary(config_text: str | None) -> str:
    text = (config_text or "").strip()
    if not text:
        return "No Burp config export supplied."
    compact = text[:3000]
    return compact + ("..." if len(text) > 3000 else "")


def _burp_screenshot_audit_summary(audit_text: str | None) -> str:
    text = (audit_text or "").strip()
    if not text:
        return "No Burp settings screenshot audit notes supplied."
    compact = text[:2000]
    return compact + ("..." if len(text) > 2000 else "")


def _loaded_burp_tools_summary(loaded_burp_tools_text: str | None) -> str:
    text = (loaded_burp_tools_text or "").strip()
    if not text:
        return "No loaded Burp tools or BApps were supplied."
    normalized = normalize_loaded_burp_tools(text)
    if normalized["summary_lines"]:
        return "\n".join(normalized["summary_lines"] + normalized["recommendation_lines"][:4])
    compact = text[:1200]
    return compact + ("..." if len(text) > 1200 else "")


def _logger_evidence_summary(logger_evidence_text: str | None) -> str:
    text = (logger_evidence_text or "").strip()
    if not text:
        return "No Logger++ evidence supplied."

    notes = []
    status_match = re.search(r"(\d{3})\s*(?:->|to)\s*(\d{3})", text)
    if status_match:
        notes.append(f"Observed status delta: {status_match.group(1)} -> {status_match.group(2)}.")
    length_match = re.search(r"(?:length|size)\s*(?:delta|change|changed|:)?\s*([+-]?\d+)", text, re.IGNORECASE)
    if length_match:
        notes.append(f"Observed response length delta: {length_match.group(1)}.")
    if re.search(r"\bheader diff\b|\bset-cookie\b|\blocation\b", text, re.IGNORECASE):
        notes.append("Header differences were noted in Logger++ evidence.")
    if re.search(r"\binteresting response\b|\bconfirmed\b|\bbaseline\b", text, re.IGNORECASE):
        notes.append("Logger++ evidence includes baseline or confirmation markers.")

    compact = text[:1600] + ("..." if len(text) > 1600 else "")
    if notes:
        return "\n".join(notes + [compact])
    return compact


def _looks_like_vision_model(model_name: str) -> bool:
    lowered = (model_name or "").strip().lower()
    return any(token in lowered for token in ("llava", "vision", "vl"))


def _resolve_vision_model_name() -> str:
    if OLLAMA_VISION_MODEL:
        return OLLAMA_VISION_MODEL
    active_model = get_active_ollama_model()
    if _looks_like_vision_model(active_model):
        return active_model
    return ""


def _normalize_screenshot_candidate(line: str) -> str:
    normalized = (line or "").strip().strip('"').strip("'")
    if normalized.startswith("- ") or normalized.startswith("* ") or normalized.startswith("• "):
        normalized = normalized[2:].strip()
    lowered = normalized.lower()
    if lowered.startswith("path:"):
        parts = normalized.split(":", 1)
        if len(parts) == 2:
            normalized = parts[1].strip()
    return normalized


def _path_from_screenshot_line(line: str) -> Path | None:
    candidate = _normalize_screenshot_candidate(line)
    if not candidate:
        return None
    lowered = candidate.lower()
    path_text = candidate
    if lowered.startswith("file://"):
        parsed = urlparse(candidate)
        path_text = unquote(parsed.path or "")
        if parsed.netloc and not path_text:
            path_text = parsed.netloc
        if re.match(r"^/[A-Za-z]:/", path_text):
            path_text = path_text[1:]
    path = Path(path_text)
    if path.suffix.lower() not in SCREENSHOT_IMAGE_EXTENSIONS:
        return None
    return path


def _extract_screenshot_paths_and_notes(audit_text: str | None) -> tuple[list[Path], list[str]]:
    paths: list[Path] = []
    notes: list[str] = []
    seen: set[str] = set()
    for raw_line in (audit_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        path = _path_from_screenshot_line(line)
        if path is None:
            notes.append(_normalize_screenshot_candidate(line))
            continue
        resolved = path.expanduser()
        key = str(resolved).lower()
        if key not in seen:
            seen.add(key)
            paths.append(resolved)
    return paths[:MAX_SCREENSHOT_IMAGES], notes


def _review_burp_settings_screenshots(payload, privacy_mode: str) -> dict[str, str]:
    raw_text = "\n".join([
        getattr(payload, "burp_screenshot_audit_text", "") or "",
        getattr(payload, "program_screenshot_audit_text", "") or "",
    ]).strip()
    image_paths, notes = _extract_screenshot_paths_and_notes(raw_text)
    if not image_paths:
        return {
            "summary": "",
            "status": "No screenshot image files were supplied for local vision review.",
        }

    vision_model = _resolve_vision_model_name()
    if not vision_model:
        return {
            "summary": "",
            "status": "Screenshot image paths were supplied, but no vision-capable Ollama model is configured. Set OLLAMA_VISION_MODEL to enable local screenshot parsing.",
        }

    encoded_images: list[str] = []
    used_files: list[str] = []
    skipped_files: list[str] = []
    for image_path in image_paths:
        try:
            resolved = image_path.resolve()
            if not resolved.exists() or not resolved.is_file():
                skipped_files.append(f"{image_path} (not found)")
                continue
            size = resolved.stat().st_size
            if size > MAX_SCREENSHOT_FILE_BYTES:
                skipped_files.append(f"{resolved} (too large)")
                continue
            encoded_images.append(base64.b64encode(resolved.read_bytes()).decode("ascii"))
            used_files.append(str(resolved))
        except Exception as exc:
            skipped_files.append(f"{image_path} ({exc})")

    if not encoded_images:
        return {
            "summary": "",
            "status": "Screenshot image paths were supplied, but none could be read successfully for local vision review.",
        }

    notes_block = "\n".join(f"- {note}" for note in notes[:8]) if notes else "- <no extra operator notes>"
    prompt = f"""
You are reviewing Burp Suite settings screenshots and bug bounty program screenshots for an MCP-grounded bug bounty testing workflow.
Only use settings or policy constraints that are actually visible in the screenshots or stated in the notes.
Do not invent hidden values, toggles, or sections.

Operator notes:
{notes_block}

Return 6 to 12 concise bullets covering:
- Burp settings section or program-rule area visible
- Current value or policy constraint if readable
- Recommended keep/change action before scanning or confirmation
- Why it matters for safe bug bounty testing or confirmation quality
- Whether AI Bridge can auto-apply it, or whether it remains manual in Burp
"""
    data = {
        "model": vision_model,
        "prompt": prompt,
        "stream": False,
        "images": encoded_images,
    }
    try:
        response = requests.post(OLLAMA_URL, json=data, timeout=OLLAMA_VISION_TIMEOUT_SECONDS)
        response.raise_for_status()
        summary = (response.json().get("response") or "").strip()
        if not summary:
            return {
                "summary": "",
                "status": "Local vision review returned no screenshot summary.",
            }
        status = f"Local screenshot review completed with {vision_model} on {len(used_files)} image(s)."
        if skipped_files:
            status += " Skipped: " + "; ".join(skipped_files[:4]) + "."
        return {
            "summary": sanitize_free_text(summary, privacy_mode),
            "status": status,
        }
    except requests.exceptions.ReadTimeout:
        return {
            "summary": "",
            "status": f"Local vision review timed out after {OLLAMA_VISION_TIMEOUT_SECONDS} seconds.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "summary": "",
            "status": f"Local vision review failed at {OLLAMA_URL}: {exc}",
        }


def _bapp_findings_summary(bapp_findings_text: str | None) -> str:
    text = (bapp_findings_text or "").strip()
    if not text:
        return "No BApp findings supplied."
    from server.bapp_adapters import normalize_bapp_findings

    normalized = normalize_bapp_findings(text)
    if normalized["summary_lines"]:
        return "\n".join(normalized["summary_lines"])
    compact = text[:2000]
    return compact + ("..." if len(text) > 2000 else "")


def _collaborator_evidence_summary(collaborator_evidence_text: str | None) -> str:
    text = (collaborator_evidence_text or "").strip()
    if not text:
        return "No Collaborator evidence supplied."
    summary = summarize_collaborator_evidence(text)
    return "\n".join(summary["summary_lines"]) if summary["summary_lines"] else "No Collaborator evidence supplied."


def _evidence_timeline_summary(entries: list[str] | None) -> str:
    if not entries:
        return "No evidence timeline entries supplied."
    trimmed = []
    for entry in entries[-6:]:
        compact = (entry or "").strip()
        if compact:
            trimmed.append(compact[:600] + ("..." if len(compact) > 600 else ""))
    return "\n\n".join(trimmed) if trimmed else "No evidence timeline entries supplied."


def _format_memory_block(memory_hits: list[dict], memory_summary: dict) -> str:
    if not memory_hits:
        return "- <no similar prior findings in local memory>"

    lines = [f"- {memory_summary['note']}"]
    for hit in memory_hits:
        vuln_classes = ", ".join(hit["fingerprint"].get("vuln_classes", [])) or "general"
        labels = ", ".join(hit.get("feedback_labels", [])) or "unrated"
        line = (
            f"- Similarity {hit['similarity']:.2f} to {hit.get('target_url') or '<unknown target>'}"
            f" | vuln classes: {vuln_classes}"
            f" | feedback: {labels}"
        )
        confirmed = ", ".join(hit.get("confirmed_classes", []))
        discarded = ", ".join(hit.get("discarded_classes", []))
        kb_titles = ", ".join(hit.get("kb_signal_titles", [])[:2])
        if confirmed:
            line += f" | confirmed: {confirmed}"
        if discarded:
            line += f" | discarded: {discarded}"
        if kb_titles:
            line += f" | kb notes: {kb_titles}"
        lines.append(line)
    return "\n".join(lines)


def _append_manual_tooling(analysis: str, manual_tooling: list[str]) -> str:
    if not manual_tooling or "Suggested Kali WSL tools for safe follow-up:" in analysis:
        return analysis
    return (
        f"{analysis}\n\nSuggested Kali WSL tools for safe follow-up:\n- "
        + "\n- ".join(manual_tooling)
    )


def _append_manual_commands(analysis: str, manual_commands: list[str]) -> str:
    if not manual_commands or "Suggested Kali WSL command templates:" in analysis:
        return analysis
    return (
        f"{analysis}\n\nSuggested Kali WSL command templates:\n- "
        + "\n- ".join(manual_commands)
    )


def _starter_payload_items(rule_context: dict) -> list[str]:
    vuln_class = ""
    if rule_context.get("matched_recipes"):
        vuln_class = (rule_context["matched_recipes"][0].get("vuln_class") or "").strip().lower()

    if vuln_class == "cache":
        return [
            "Cache-Control: no-cache",
            "Cache-Control: no-store",
            "Cache-Control: max-age=0",
            "Pragma: no-cache",
            "Accept-Encoding: identity",
            "<authenticated vs unauthenticated>",
        ]

    payload_recommendations = rule_context.get("aggregate", {}).get("payload_recommendations", []) or []
    if not payload_recommendations:
        return []

    primary = payload_recommendations[0]
    raw_list = primary.split("Starter list:", 1)[1] if "Starter list:" in primary else primary
    items = []
    for chunk in raw_list.split(","):
        normalized = chunk.strip().strip("`")
        if normalized and normalized not in items:
            items.append(normalized)
    return items[:6]


def _direct_follow_up_answer(payload, rule_context: dict) -> str:
    request = _suggestion_follow_up_request(payload)
    if not request:
        return ""

    intents = _follow_up_intents(request)
    aggregate = rule_context.get("aggregate", {})
    request_plan = aggregate.get("request_plan", []) or []
    manual_tooling = aggregate.get("manual_tooling", []) or []
    manual_commands = aggregate.get("manual_commands", []) or []
    seclists_path = aggregate.get("seclists_path", "") or ""
    payload_items = _starter_payload_items(rule_context)

    target_focus = "the identified target field or route"
    primary_mode = "Repeater first"
    for item in request_plan:
        if item.startswith("Target parameter:"):
            target_focus = item.split(":", 1)[1].strip()
        elif item.startswith("Primary mode:"):
            primary_mode = item.split(":", 1)[1].strip()

    lower_request = request.lower()
    lines = [
        "Direct answer to your follow-up request:",
        f"- Request: {request}",
    ]

    if intents["steps"]:
        lines.extend([
            "Burp Repeater steps:",
            "1. Send the captured request to Burp Repeater and keep one tab unchanged as the baseline.",
            "2. Duplicate the baseline tab into Tab 2, Tab 3, and Tab 4 so each tab changes only one input at a time.",
            f"3. Keep your edits focused on {target_focus} and stay in `{primary_mode}` unless one response proves a different lane is needed.",
            "4. In Tab 2 apply the first payload only, in Tab 3 apply the second payload only, and in Tab 4 apply the third payload only, then send all tabs.",
            "5. Compare each tab against the baseline for status code, content length, body delta, cache or auth headers, and redirect behavior before trying more payloads.",
            "6. If one tab produces the first meaningful delta, clone only that tab and iterate one change at a time instead of broadening all variants.",
            "7. Move the interesting pair into Comparer if the body delta is noisy and you need a cleaner diff before the next round.",
            "8. Stop the sequence as soon as one variant is stable enough to explain the next exact hypothesis.",
        ])

    if intents["intruder"]:
        lines.extend([
            "Burp Intruder steps:",
            "1. Send the same baseline request to Intruder only after Repeater shows one meaningful variation worth expanding.",
            "2. Clear all positions, then mark only the exact insertion point inside the target parameter or header under test.",
            "3. Use Sniper for one insertion point; only switch to Pitchfork or Cluster Bomb if you are deliberately testing paired inputs.",
            "4. Load the payloads in the exact order shown below so the first run stays short and explainable.",
            "5. Add grep or response markers for status code, content length, cache headers, reflected strings, and any redirect location change.",
            "6. Start with a very small payload set, review the first responses, and stop immediately if no differentiating signal appears.",
        ])

    if intents["payloads"]:
        lines.append("Payloads to start with:")
        if payload_items:
            for index, item in enumerate(payload_items[:6], start=1):
                lines.append(f"{index}. {item}")
        else:
            lines.append("1. Use the starter payloads already shown in the Payload Lists panel before expanding into a larger list.")

        if seclists_path:
            if rule_context.get("matched_recipes") and (rule_context["matched_recipes"][0].get("vuln_class") or "").strip().lower() == "cache":
                lines.append(
                    f"- For this cache-oriented review, a short hand-curated list is better than a large SecLists run. Only reach for `{seclists_path}` after one manual variation produces a meaningful delta."
                )
            else:
                lines.append(f"- If one manual variation proves meaningful, expand carefully with `{seclists_path}`.")

    if intents["tools"]:
        lines.append("Kali tool order:")
        if manual_tooling:
            lines.append(f"1. Start with {manual_tooling[0]}.")
        if manual_commands:
            lines.append(f"2. First command: {manual_commands[0]}.")
            for index, command in enumerate(manual_commands[1:3], start=3):
                lines.append(f"{index}. Next command only if the earlier step produced a useful delta: {command}.")

    return "\n".join(lines)


def _append_direct_follow_up_answer(analysis: str, payload, rule_context: dict) -> str:
    direct_answer = _direct_follow_up_answer(payload, rule_context)
    if not direct_answer or "Direct answer to your follow-up request:" in analysis:
        return analysis
    return f"{analysis}\n\n{direct_answer}"


def _apply_memory_hints(aggregate: dict, memory_summary: dict) -> dict:
    if not memory_summary.get("total_hits"):
        return aggregate

    enriched = dict(aggregate)
    analysis = enriched.get("analysis", "")
    analysis = (
        f"{analysis}\n\nPrior local memory:\n"
        f"- {memory_summary['note']}"
    )
    if memory_summary.get("top_targets"):
        analysis += "\n- Similar prior targets: " + ", ".join(memory_summary["top_targets"])
    if memory_summary.get("preferred_kb_titles"):
        analysis += "\n- Confirmed local KB notes to prioritize: " + ", ".join(memory_summary["preferred_kb_titles"])
    if memory_summary.get("deprioritized_kb_titles"):
        analysis += "\n- Local KB notes recently deprioritized: " + ", ".join(memory_summary["deprioritized_kb_titles"])
    enriched["analysis"] = _append_manual_tooling(analysis, enriched.get("manual_tooling", []))
    enriched["analysis"] = _append_manual_commands(enriched["analysis"], enriched.get("manual_commands", []))

    questions = list(enriched.get("questions_for_user", []))
    if memory_summary.get("exact_matches"):
        exact_match_question = (
            "Do you want to compare this response against prior captures of the same normalized endpoint to confirm whether the behavior is stable or role-dependent?"
        )
        if exact_match_question not in questions:
            questions.append(exact_match_question)
    enriched["questions_for_user"] = questions[:3]
    return enriched


def _apply_operator_context(aggregate: dict, payload) -> dict:
    enriched = dict(aggregate)
    operator_answers = getattr(payload, "operator_answers", None) or {}
    tool_help_text = getattr(payload, "tool_help_text", "") or ""
    context_lines = []

    if operator_answers:
        context_lines.append("Operator answers received:")
        for question, answer in operator_answers.items():
            normalized_answer = (answer or "").strip()
            if normalized_answer:
                context_lines.append(f"- {question}: {normalized_answer}")

    if tool_help_text.strip():
        context_lines.append(
            "Tool help text received for command shaping. Use it only to choose safe syntax and conservative rate limits, not to evade defensive controls."
        )
    if (getattr(payload, "scope_includes_text", "") or "").strip() or (getattr(payload, "scope_excludes_text", "") or "").strip():
        context_lines.append("Program scope details were provided and should constrain any proposed follow-up.")
    if (getattr(payload, "rate_limit_text", "") or "").strip() or (getattr(payload, "max_concurrency_text", "") or "").strip():
        context_lines.append("Program rate or concurrency limits were provided and should bound any suggested command.")
    if (getattr(payload, "custom_headers_text", "") or "").strip():
        context_lines.append("Custom headers were provided and should be carried into compatible command templates.")
    if (getattr(payload, "tool_results_text", "") or "").strip():
        context_lines.append("Manual tool results or file references were supplied for evidence-based follow-up.")
    if (getattr(payload, "loaded_burp_tools_text", "") or "").strip():
        context_lines.append("Loaded Burp tools or BApps were supplied and should be preferred before missing external tools.")
    if (getattr(payload, "response_delta_text", "") or "").strip():
        context_lines.append("An explicit response-delta note was supplied for the latest approved comparison.")
    if (getattr(payload, "logger_evidence_text", "") or "").strip():
        context_lines.append("Logger++ evidence was supplied and should be treated as higher-signal request or response diff evidence.")
    if (getattr(payload, "collaborator_evidence_text", "") or "").strip():
        context_lines.append("Collaborator-related observations were supplied for passive interpretation and report wording.")
    if getattr(payload, "evidence_timeline_entries", None):
        context_lines.append(
            f"Evidence timeline entries were supplied ({len(getattr(payload, 'evidence_timeline_entries', []))} item(s)) and should be used as a sequence of prior observations."
        )

    if context_lines:
        enriched["analysis"] = f"{enriched.get('analysis', '')}\n\n" + "\n".join(context_lines)

        questions = list(enriched.get("questions_for_user", []))
        if operator_answers:
            confirmation_question = "Do you want the next follow-up to narrow to one confirmed hypothesis based on your answers?"
            if confirmation_question not in questions:
                questions.append(confirmation_question)
        enriched["questions_for_user"] = questions[:3]

    return enriched


def _fallback_analysis(payload, rule_context: dict, memory_summary: dict, reason: str | None = None) -> dict:
    aggregate = dict(rule_context["aggregate"])
    aggregate = _apply_memory_hints(aggregate, memory_summary)
    aggregate = _apply_operator_context(aggregate, payload)
    aggregate["analysis"] = _append_direct_follow_up_answer(aggregate.get("analysis", ""), payload, rule_context)
    complexity = rule_context["complexity"]
    profile_name = normalize_profile_name(getattr(payload, "selected_profile", ""))
    review_scope = rule_context.get("review_scope", {})
    aggregate["analysis"] = (
        f"Profile: {profile_name}\n"
        f"Review scope classes: {', '.join(review_scope.get('allowed_classes', [])) or '<none>'}\n"
        f"Model: {get_active_ollama_model()}\n"
        f"Complexity estimate: {complexity['level']} ({complexity['eta']}). "
        f"{complexity['recommendation']}\n\n{aggregate['analysis']}"
    )
    if reason:
        aggregate["analysis"] = f"{aggregate['analysis']}\n\nModel refinement unavailable: {reason}"
        questions = list(aggregate.get("questions_for_user", []))
        complexity_question = (
            "Do you want to reduce scope and test one request or one hypothesis at a time to shorten local analysis time?"
        )
        if complexity_question not in questions:
            questions.append(complexity_question)
        aggregate["questions_for_user"] = questions[:3]
    return aggregate


def _build_kb_query(payload, rule_context: dict) -> str:
    recipe_titles = [recipe["title"] for recipe in rule_context["matched_recipes"][:3]]
    param_names = rule_context["features"]["param_names"][:6]
    query_parts = [
        payload.target_url or "",
        payload.http_method or "",
        " ".join(recipe_titles),
        " ".join(param_names),
    ]
    return " ".join(part for part in query_parts if part).strip()


def _looks_like_static_asset(payload, rule_context: dict) -> bool:
    parsed = urlparse(getattr(payload, "target_url", "") or "")
    path = (parsed.path or "").lower()
    if any(path.endswith(extension) for extension in STATIC_ASSET_EXTENSIONS):
        return True

    response_content_type = (rule_context["features"].get("response_content_type") or "").lower()
    request_content_type = (rule_context["features"].get("request_content_type") or "").lower()
    if any(marker in response_content_type for marker in ("image/", "font/", "text/css", "javascript", "manifest")):
        return True
    if path.endswith("/site.webmanifest") or path.endswith("/manifest.json"):
        return True
    return False


def _has_extra_operator_context(payload) -> bool:
    return any([
        bool(getattr(payload, "operator_answers", None)),
        bool((getattr(payload, "tool_help_text", "") or "").strip()),
        bool((getattr(payload, "scope_includes_text", "") or "").strip()),
        bool((getattr(payload, "scope_excludes_text", "") or "").strip()),
        bool((getattr(payload, "rate_limit_text", "") or "").strip()),
        bool((getattr(payload, "max_concurrency_text", "") or "").strip()),
        bool((getattr(payload, "custom_headers_text", "") or "").strip()),
        bool((getattr(payload, "program_policy_text", "") or "").strip()),
        bool((getattr(payload, "saved_program_policy_text", "") or "").strip()),
        bool((getattr(payload, "tool_results_text", "") or "").strip()),
        bool((getattr(payload, "burp_config_export_text", "") or "").strip()),
        bool((getattr(payload, "burp_screenshot_audit_text", "") or "").strip()),
        bool((getattr(payload, "loaded_burp_tools_text", "") or "").strip()),
        bool((getattr(payload, "program_screenshot_audit_text", "") or "").strip()),
        bool((getattr(payload, "response_delta_text", "") or "").strip()),
        bool((getattr(payload, "bapp_findings_text", "") or "").strip()),
        bool((getattr(payload, "logger_evidence_text", "") or "").strip()),
        bool((getattr(payload, "collaborator_evidence_text", "") or "").strip()),
        bool(getattr(payload, "evidence_timeline_entries", None)),
    ])


def _skip_model_reason(payload, rule_context: dict) -> str | None:
    if not SKIP_MODEL_FOR_LOW_SIGNAL:
        return None

    if _looks_like_static_asset(payload, rule_context):
        if _has_extra_operator_context(payload):
            return None
        return "The selected exchange looks like a static asset or manifest and no extra operator context was supplied, so model refinement was skipped."

    if rule_context["complexity"]["level"] == "low" and not rule_context["matched_recipes"] and not _has_extra_operator_context(payload):
        return "No strong deterministic signal or extra operator context was present, so model refinement was skipped."

    return None


def analyze_traffic(payload) -> dict:
    helper_names = (
        "normalize_profile_name",
        "get_profile",
        "build_rule_context",
        "build_endpoint_fingerprint",
        "find_similar_history",
        "summarize_similar_findings",
        "describe_history_correlation",
        "build_kb_query",
        "search_notes_detailed",
        "query_guidance_packs",
        "query_review_examples",
        "summarize_collaborator_evidence",
        "review_burp_settings_screenshots",
        "fallback_analysis",
        "skip_model_reason",
        "suggestion_follow_up_request",
        "summarize_http_message",
        "sanitize_http_message",
        "build_analysis_prompt",
        "format_operator_answers",
        "tool_help_summary",
        "inventory_summary_text",
        "sanitize_free_text",
        "loaded_burp_tools_summary",
        "format_program_context",
        "tool_results_summary",
        "burp_config_export_summary",
        "burp_screenshot_audit_summary",
        "bapp_findings_summary",
        "logger_evidence_summary",
        "collaborator_evidence_summary",
        "evidence_timeline_summary",
        "follow_up_prompt_instructions",
        "scanner_issue_context",
        "burp_origin_context",
        "format_list",
        "format_recipe_block",
        "format_memory_block",
        "format_model_trace_entry",
        "build_model_execution_summary",
        "build_provider_failover",
        "finalize_fallback_response",
        "configured_model_providers",
        "call_mcp_provider",
        "call_ollama_provider",
        "format_ollama_request_error",
        "enforce_candidate_planner_schema",
        "normalize_model_candidate",
        "merge_model_candidates",
        "missing_model_fields",
        "build_result_analysis",
        "append_manual_tooling",
        "append_manual_commands",
        "append_direct_follow_up_answer",
        "attach_execution_metadata",
        "effective_privacy_mode",
    )
    helpers = {name: globals()[f"_{name}"] if f"_{name}" in globals() else globals()[name] for name in helper_names}
    constants = {
        "max_request_header_lines": MAX_REQUEST_HEADER_LINES,
        "max_response_header_lines": MAX_RESPONSE_HEADER_LINES,
        "max_request_body_preview_chars": MAX_REQUEST_BODY_PREVIEW_CHARS,
        "max_response_body_preview_chars": MAX_RESPONSE_BODY_PREVIEW_CHARS,
        "model_required_fields": _MODEL_REQUIRED_FIELDS,
        "ollama_timeout_seconds": OLLAMA_TIMEOUT_SECONDS,
    }
    return _execute_advisory_flow(payload, helpers=helpers, constants=constants)


from server.providers.advisory_context_service import (
    apply_memory_hints as _apply_memory_hints,
    apply_operator_context as _apply_operator_context,
    build_kb_query as _build_kb_query,
    effective_privacy_mode as _effective_privacy_mode,
    fallback_analysis as _fallback_analysis,
    has_extra_operator_context as _has_extra_operator_context,
    looks_like_static_asset as _looks_like_static_asset,
    skip_model_reason as _skip_model_reason,
)
from server.local_guidance_db import query_guidance_packs as _query_guidance_packs
from server.review_dataset import query_review_examples as _query_review_examples
from server.providers.model_execution_service import (
    MODEL_REQUIRED_FIELDS as _MODEL_REQUIRED_FIELDS,
    append_model_execution_details as _append_model_execution_details,
    attach_execution_metadata as _attach_execution_metadata,
    build_provider_failover as _build_provider_failover,
    build_mcp_arguments as _build_mcp_arguments,
    build_model_execution_summary as _build_model_execution_summary,
    call_mcp_provider as _call_mcp_provider,
    call_ollama_provider as _call_ollama_provider,
    candidate_ollama_text_urls as _candidate_ollama_text_urls,
    configured_model_providers as _configured_model_providers,
    extract_mcp_candidate as _extract_mcp_candidate,
    enforce_candidate_planner_schema as _enforce_candidate_planner_schema,
    finalize_fallback_response as _finalize_fallback_response,
    format_model_trace_entry as _format_model_trace_entry,
    format_ollama_request_error as _format_ollama_request_error,
    is_populated_model_value as _is_populated_model_value,
    mcp_server_label as _mcp_server_label,
    merge_model_candidates as _merge_model_candidates,
    missing_model_fields as _missing_model_fields,
    normalize_model_candidate as _normalize_model_candidate,
    ollama_text_response as _ollama_text_response,
)
from server.providers.prompt_builder_service import (
    build_analysis_prompt as _build_analysis_prompt,
    build_result_analysis as _build_result_analysis,
)
from server.providers.advisory_flow_service import execute_advisory_flow as _execute_advisory_flow
