PLAYBOOKS = {
    "access-control": {
        "why": "Object identifiers, role hints, or authorization context suggest comparing access consistency across sessions or tenants.",
        "evidence": "Capture the baseline response, then compare status code, body length, and object ownership details across approved role or session variants.",
        "steps": "Use Burp HTTP history to align the original request with one manually approved variant and note whether authorization, ownership, or field-level exposure changes.",
        "confidence": "Increase confidence if the same object identifier yields materially different authorization outcomes across valid roles or sessions. Decrease confidence if behavior stays consistent.",
    },
    "authentication": {
        "why": "Bearer tokens, login paths, or session transitions suggest auth-context review.",
        "evidence": "Record the baseline authenticated and unauthenticated responses, including status, redirect behavior, and token/session transitions.",
        "steps": "Compare adjacent login, refresh, logout, or token-bearing requests in Burp history before deciding whether the issue is auth logic or only session state.",
        "confidence": "Increase confidence when auth state changes behavior in a way that should not be allowed. Decrease confidence if the variation is explained by normal session expiry or redirect handling.",
    },
    "business-logic": {
        "why": "Workflow-like endpoints or repeated state-changing requests suggest sequencing or workflow abuse review.",
        "evidence": "Collect the baseline request sequence and compare one approved reordered, repeated, or skipped-step variant in Burp history.",
        "steps": "Use the evidence timeline to document the baseline sequence, the modified sequence, and the exact server-side difference you observed.",
        "confidence": "Increase confidence when a workflow step can be skipped, repeated, or reordered without the expected server-side guardrails.",
    },
    "cache": {
        "why": "Caching headers or cache-like behavior suggest cache-control review.",
        "evidence": "Compare cache headers, vary behavior, and repeated responses for the same resource under the same and changed request conditions.",
        "steps": "Use Burp history to compare repeated GET responses and note changes in cache-control, vary, etag, or content exposure.",
        "confidence": "Increase confidence when protected or user-specific content appears cacheable or inconsistent across comparable requests.",
    },
    "command-injection": {
        "why": "Input-to-system command clues suggest server-side command execution or shell-adjacent processing risk.",
        "evidence": "Capture the exact baseline input handling and compare one harmless structural variation at a time while recording parser, validation, timing, or output differences.",
        "steps": "Use Burp Repeater first to isolate the exact input field and compare one controlled delimiter, wrapper, or encoding variation at a time before considering a broader Intruder list.",
        "confidence": "Increase confidence when the same input family repeatedly changes server-side processing in a way that suggests shell, command, or OS-level handling rather than normal validation.",
    },
    "cors": {
        "why": "Origin-related headers or CORS response headers suggest cross-origin trust review.",
        "evidence": "Collect baseline and manually approved origin-varied responses, then compare Access-Control-Allow-* behavior in Burp history.",
        "steps": "Record whether origin reflection, credentials, or wildcard behavior changes across approved request variants.",
        "confidence": "Increase confidence if reflected or permissive CORS behavior appears on sensitive endpoints with credentials or protected data.",
    },
    "crypto-failures": {
        "why": "Transport, cookie, or exposed-key clues suggest missing cryptographic protections.",
        "evidence": "Capture whether the same sensitive flow is reachable over plain HTTP, whether cookies lack Secure, and whether any key material appears in responses.",
        "steps": "Use Burp history to compare transport, redirects, cookie flags, and exposed material across the same route without broad host scanning first.",
        "confidence": "Increase confidence when sensitive traffic or session state remains usable without the expected transport or cryptographic controls.",
    },
    "csrf": {
        "why": "State-changing forms or browser-bound flows without obvious anti-CSRF markers suggest CSRF review.",
        "evidence": "Capture the baseline form or state-changing request and compare token, Origin, and Referer handling across approved manual variants.",
        "steps": "Use Burp history to document whether the server requires a token or browser-origin signal consistently.",
        "confidence": "Increase confidence when a state-changing flow succeeds without the expected token or origin checks.",
    },
    "deserialization": {
        "why": "Serialized-object style markers suggest the server may deserialize client-controlled structures.",
        "evidence": "Capture the exact baseline opaque blob or object input and compare one approved structural variation for parser or integrity-check differences.",
        "steps": "Document whether the server rejects, normalizes, or errors on the structured input rather than jumping from one parser error to a full finding.",
        "confidence": "Increase confidence when the same structured input family repeatedly produces type, parser, or integrity-handling clues tied to server-side deserialization.",
    },
    "file-upload": {
        "why": "Multipart uploads or upload-adjacent endpoints suggest upload handling review.",
        "evidence": "Compare baseline upload acceptance, retrieval, preview, and metadata behavior for approved file-handling tests.",
        "steps": "Record content type, filename handling, storage path clues, and any preview/retrieval endpoints seen in Burp history.",
        "confidence": "Increase confidence if upload validation or retrieval controls differ from the expected server-side policy.",
    },
    "graphql": {
        "why": "The request or response looks like GraphQL traffic with schema and field-level authorization considerations.",
        "evidence": "Capture the baseline operation and compare one approved field, variable, or introspection-related variation in Burp history.",
        "steps": "Record whether the schema, error shape, or object-level authorization surface changes when you adjust only one GraphQL input at a time.",
        "confidence": "Increase confidence when GraphQL-specific behavior exposes schema, data, or authorization paths that normal REST-style controls would not allow.",
    },
    "http-request-smuggling": {
        "why": "Conflicting request-length framing suggests front-end versus back-end parsing differences.",
        "evidence": "Capture the exact baseline framing and compare one approved header-framing variation while recording mismatched responses or queue behavior.",
        "steps": "Use Burp Repeater to preserve the original request framing and note any front-end/back-end mismatch without broad fuzzing.",
        "confidence": "Increase confidence when one controlled framing change consistently alters how different components parse the same request.",
    },
    "information-disclosure": {
        "why": "Verbose errors, stack traces, or passive disclosures suggest disclosure review.",
        "evidence": "Capture the baseline response and compare header/body disclosures across adjacent endpoints or approved malformed-input observations.",
        "steps": "Use Burp history to diff verbose error responses, headers, and metadata exposure instead of relying on one isolated response.",
        "confidence": "Increase confidence when the server leaks implementation details, secrets, or debug information beyond expected behavior.",
    },
    "input-validation": {
        "why": "Input-rich parameters or reflected/search-like parameters suggest validation review.",
        "evidence": "Compare the baseline response with one approved benign structural variation and note validation, encoding, and normalization behavior.",
        "steps": "Use Burp history to document whether the server normalizes, rejects, or inconsistently processes structurally similar inputs.",
        "confidence": "Increase confidence when input handling differs in a way that weakens server-side validation or trust boundaries.",
    },
    "insecure-design": {
        "why": "The workflow appears to rely on client-visible sequencing or state assumptions instead of strong server-side guardrails.",
        "evidence": "Capture the intended workflow and compare one approved replay, skip, reorder, or state-value variation.",
        "steps": "Use Burp history and the evidence timeline to show exactly which design assumption the server failed to enforce.",
        "confidence": "Increase confidence when the server accepts a workflow path that should be blocked by business design rather than by simple input validation.",
    },
    "jwt-token": {
        "why": "JWT-like authorization context suggests token-claim and trust-boundary review.",
        "evidence": "Compare baseline token-bearing requests with approved role, audience, or token-state observations from Burp history and your notes.",
        "steps": "Document claims, header structure, and server-side behavior changes rather than focusing on token mutation.",
        "confidence": "Increase confidence when role, audience, or token-state handling appears inconsistent with the protected resource.",
    },
    "mass-assignment": {
        "why": "Sensitive JSON field names suggest the server may auto-bind client-controlled properties that should remain server-managed.",
        "evidence": "Capture the baseline JSON body and compare one privileged field change at a time while recording whether the server accepts, ignores, or normalizes it.",
        "steps": "Use Burp history to show which fields the client can set and whether the resulting state proves the server trusted them.",
        "confidence": "Increase confidence when server-managed fields such as roles or permissions are silently accepted from the client.",
    },
    "open-redirect": {
        "why": "Redirect-like parameters suggest redirect target validation review.",
        "evidence": "Capture the baseline redirect behavior and compare target validation or allowlist enforcement across approved manual observations.",
        "steps": "Use Burp history to compare how the application handles redirect-like parameters in similar endpoints.",
        "confidence": "Increase confidence when external or unsafe redirect targets are accepted where a strict allowlist should apply.",
    },
    "path-traversal": {
        "why": "File or path-style inputs suggest local file access or template path normalization review.",
        "evidence": "Capture the baseline file/path input and compare one path variation at a time while recording normalization, rejection, or retrieval differences.",
        "steps": "Use Burp history to document whether the server canonicalizes paths safely or exposes filesystem-oriented behavior.",
        "confidence": "Increase confidence when one controlled path variation changes which resource the server reads or rejects.",
    },
    "race-condition": {
        "why": "The endpoint appears to perform a state-changing workflow action that may be sensitive to parallel execution.",
        "evidence": "Capture the baseline action and compare the outcome when the same approved request is replayed in close succession or parallel tabs.",
        "steps": "Use Burp Repeater tabs and your evidence timeline to show whether the server processed both operations or enforced one-time semantics.",
        "confidence": "Increase confidence when parallel or rapid duplicate requests lead to inconsistent balances, redemptions, or state changes.",
    },
    "security-misconfiguration": {
        "why": "Missing headers, weak defaults, or passive platform clues suggest configuration review.",
        "evidence": "Compare baseline headers and default behavior across nearby public, authenticated, and static endpoints in Burp history.",
        "steps": "Document which protections are missing consistently and which vary by endpoint class.",
        "confidence": "Increase confidence when the same missing protection repeats across sensitive application areas.",
    },
    "secret-exposure": {
        "why": "The response appears to include key material, tokens, or other secrets that should remain server-side.",
        "evidence": "Capture the exact response segment and compare whether the same leakage appears across baseline, error, and adjacent debug/config responses.",
        "steps": "Use Burp history to show where the secret appears and whether it is stable, role-dependent, or only exposed on exceptional paths.",
        "confidence": "Increase confidence when real credentials, keys, or private material appear in client-visible responses without a legitimate reason.",
    },
    "session-management": {
        "why": "Cookies, login/logout flows, or session transitions suggest session review.",
        "evidence": "Capture session establishment, use, renewal, and logout behavior across baseline and approved manual observations.",
        "steps": "Use Burp history to compare cookie flags, redirects, logout invalidation, and post-logout access behavior.",
        "confidence": "Increase confidence when session boundaries or invalidation behave inconsistently with expected security controls.",
    },
    "sqli": {
        "why": "Backend-style errors, identifier parameters, or data access patterns suggest injection suspicion scoring.",
        "evidence": "Compare baseline and approved benign structural input variations for validation, error handling, and query-like behavior in Burp history.",
        "steps": "Record whether the server reveals query-handling differences, timing anomalies, or error signatures across approved manual comparisons.",
        "confidence": "Increase confidence when the same input family repeatedly triggers backend query-like behavior that normal validation should not allow.",
    },
    "ssti": {
        "why": "Template-like inputs on rendering routes suggest possible server-side template evaluation.",
        "evidence": "Capture the baseline rendering behavior and compare one approved expression-style variation to see whether the input is escaped, reflected, or evaluated.",
        "steps": "Use Burp history to record the rendering context and any engine-specific error clues without escalating from one marker immediately.",
        "confidence": "Increase confidence when template syntax is evaluated or handled inconsistently with normal escaping.",
    },
    "ssrf": {
        "why": "URL-like parameters or fetch behavior suggest server-side request handling review.",
        "evidence": "Document baseline handling of URL-like parameters and compare server-side fetch clues across approved manual observations.",
        "steps": "Use Burp history and pasted evidence to note whether the application appears to make server-side outbound requests or normalizes external targets.",
        "confidence": "Increase confidence when server-side fetch behavior is clearly implied by consistent response-side evidence.",
    },
    "xss": {
        "why": "Reflected or search-like input handling suggests output-context review.",
        "evidence": "Capture where the input appears in the response, what encoding is applied, and whether the reflection context changes across approved manual observations.",
        "steps": "Use Burp history to compare reflection context, output encoding, and template placement rather than focusing on exploit strings.",
        "confidence": "Increase confidence when reflection occurs in a high-risk context with weak or inconsistent encoding.",
    },
    "xxe": {
        "why": "XML parsing indicators suggest XML parser behavior review.",
        "evidence": "Capture the baseline XML handling behavior and compare parser error or normalization differences across approved manual XML observations.",
        "steps": "Use Burp history to record whether the endpoint truly parses XML and how it responds to structurally different but harmless XML inputs.",
        "confidence": "Increase confidence when the parser behavior suggests unsafe XML processing instead of strict schema or parser controls.",
    },
}


def build_confirmation_playbooks(matched_recipes: list[dict]) -> list[str]:
    if not matched_recipes:
        return [
            "General confirmation playbook: capture a clean baseline, compare one approved manual variation in Burp HTTP history, and only upgrade confidence when the server-side difference is clear and repeatable."
        ]

    playbooks = []
    seen = set()
    for recipe in matched_recipes[:4]:
        vuln_class = recipe.get("vuln_class", "general")
        if vuln_class in seen:
            continue
        seen.add(vuln_class)
        details = PLAYBOOKS.get(vuln_class)
        if not details:
            continue
        playbooks.append(
            f"[{vuln_class}] Why suspected: {details['why']} "
            f"Evidence to collect: {details['evidence']} "
            f"Safe comparison steps: {details['steps']} "
            f"Confidence guidance: {details['confidence']}"
        )
    return playbooks[:6] or [
        "General confirmation playbook: capture a clean baseline, compare one approved manual variation in Burp HTTP history, and only upgrade confidence when the server-side difference is clear and repeatable."
    ]
