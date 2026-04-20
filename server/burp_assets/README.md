# Burp Starter Assets

This directory holds the Burp-side asset pack that the AI Bridge recommends after MCP context, scanner issues, and manual workflow state have already narrowed the problem to one request family.

These assets are designed to improve signal quality, not to replace operator judgment.

Principles:

- keep checks bounded to one issue family
- keep all traffic user-triggered
- use MCP context before importing a pack
- prefer one passive or bounded-active check plus one extraction-oriented Bambda

Subdirectories:

- `custom_scan_checks/`
- `bambda/`

Recommended workflow:

1. Let the bridge identify the current vuln class and request family from MCP context.
2. Import the matching Bambda pack first so identifiers, sinks, or state markers are visible.
3. Import one matching custom scan check only if it helps confirm the same request family.
4. Stop after one reproducible high-signal artifact and move back to Repeater or report preparation.

This pack is production-oriented starter material. It is intentionally conservative and should still be tuned against your own targets, accepted reports, and false-positive history.

Feedback loop:

- record high-signal or false-positive outcomes with `python -m server asset-feedback ...`
- keep MCP enabled so the bridge can rank packs against the real request family and target partition
- import accepted or downgraded regression examples with `python -m server review-import ...` so review-dataset retrieval stays grounded in real outcomes
