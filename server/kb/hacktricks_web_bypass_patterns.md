Title: HackTricks Web Bypass Patterns
Source: https://book.hacktricks.wiki/
Tags: hacktricks, bypass, cors, csrf, ssrf, auth-bypass

# HackTricks Web Bypass Patterns

## Focus Areas
- Bypass patterns around access control and request trust
- Origin and header manipulation ideas
- URL-based server fetch behavior and SSRF-style thinking
- CORS edge cases and trust mistakes
- Upload, parser, and redirect corner cases

## Signals
- URL-like inputs such as `url`, `callback`, `redirect`, `next`, `feed`
- Endpoints that trust client-controlled identifiers or role indicators
- Broad CORS headers, wildcard origins, or credentialed cross-origin behavior
- File uploads or parser-driven body formats

## Validation Approach
- Reduce scope to one trust boundary at a time
- Compare same request across different auth states
- Change a single header, token, URL parameter, or identifier in each pass
- Record which controls are server-enforced versus browser-enforced

## Burp Relevance
- Best used as a source of bypass hypotheses after a deterministic rule hit
- Strong fit for Repeater-based variant testing and side-by-side comparison
