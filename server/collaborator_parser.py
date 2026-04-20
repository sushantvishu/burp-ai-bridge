from __future__ import annotations

import re


def summarize_collaborator_evidence(text: str | None) -> dict:
    normalized = (text or "").strip()
    if not normalized:
        return {
            "summary_lines": [],
            "confidence_notes": [],
            "report_notes": [],
            "dns_hits": 0,
            "http_hits": 0,
            "smtp_hits": 0,
            "has_positive_interaction": False,
            "has_negative_interaction": False,
        }

    lower = normalized.lower()
    dns_hits = len(re.findall(r"\bdns\b", lower))
    http_hits = len(re.findall(r"\bhttp\b", lower))
    smtp_hits = len(re.findall(r"\bsmtp\b", lower))
    raw_hits = len(re.findall(r"\binteraction\b|\bcallback\b|\bpoll\b", lower))

    summary_lines = []
    if dns_hits:
        summary_lines.append(f"Collaborator evidence mentions DNS interactions {dns_hits} time(s).")
    if http_hits:
        summary_lines.append(f"Collaborator evidence mentions HTTP interactions {http_hits} time(s).")
    if smtp_hits:
        summary_lines.append(f"Collaborator evidence mentions SMTP interactions {smtp_hits} time(s).")
    if raw_hits and not summary_lines:
        summary_lines.append("Collaborator evidence mentions callback-style interactions.")

    if "no interaction" in lower or "none observed" in lower:
        summary_lines.append("The pasted evidence explicitly says no Collaborator interaction was observed.")
    has_negative_interaction = "no interaction" in lower or "none observed" in lower
    has_positive_interaction = bool(dns_hits or http_hits or smtp_hits or raw_hits) and not has_negative_interaction

    compact = normalized[:1200] + ("..." if len(normalized) > 1200 else "")
    summary_lines.append("Collaborator notes preview: " + compact.replace("\r\n", " ").replace("\n", " "))

    confidence_notes = []
    if dns_hits or http_hits or smtp_hits:
        confidence_notes.append(
            "Treat Collaborator callbacks as corroborating evidence only after you map them back to a specific in-scope request and timestamp."
        )
    else:
        confidence_notes.append(
            "No strong protocol-specific Collaborator signal was parsed from the pasted notes; keep the confidence conservative."
        )

    report_notes = [
        "If you include Collaborator observations in a report, describe the observed protocol and timing without overstating exploitability.",
        "Link the callback observation to the exact request variant and the corresponding Burp HTTP history entry where possible.",
    ]

    return {
        "summary_lines": summary_lines[:6],
        "confidence_notes": confidence_notes[:3],
        "report_notes": report_notes[:3],
        "dns_hits": dns_hits,
        "http_hits": http_hits,
        "smtp_hits": smtp_hits,
        "has_positive_interaction": has_positive_interaction,
        "has_negative_interaction": has_negative_interaction,
    }
