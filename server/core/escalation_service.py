from copy import deepcopy
from typing import Any

from server.core.program_policy_service import assess_high_risk_escalation_policy


_ALIASES = {
    "idor": "authorization",
    "access-control": "authorization",
    "broken-access-control": "authorization",
    "auth-bypass": "authentication",
    "authentication-bypass": "authentication",
    "session": "session-management",
    "sqli": "injection",
    "sql-injection": "injection",
    "ssti": "template-injection",
    "server-side-template-injection": "template-injection",
    "lfi": "file-read",
    "rfi": "file-read",
    "path-traversal": "file-read",
    "smuggling": "http-request-smuggling",
    "request-smuggling": "http-request-smuggling",
    "desync": "http-request-smuggling",
    "cache-poisoning": "web-cache-poisoning",
    "cache-deception": "web-cache-poisoning",
    "mass-assignment": "mass-assignment",
    "host-header-injection": "host-header",
}


_PROFILES = {
    "authorization": {
        "profile_name": "authorization-boundary",
        "baseline_confirmation": "Capture one role-separated diff for the same object or action before claiming broader access impact.",
        "safe_steps": [
            "Compare the same object or action across two permitted identities with the smallest allowed variable change.",
            "Check whether the confirmed boundary issue also affects list, search, export, or administrative views without modifying data.",
        ],
        "expansion_paths": [
            "Escalate from single-record access into cross-account, cross-role, or tenant-wide exposure only after the same boundary failure repeats.",
            "Raise impact when the same weakness reaches privileged actions, bulk export, or administrative visibility.",
        ],
        "required_evidence": [
            "One baseline artifact and one role-separated comparison artifact tied to the same object or action.",
            "A note showing which fields, records, or actions changed across identities.",
        ],
        "stop_conditions": [
            "Inform the user about modifying other users' data or performing irreversible state changes and ask for permission from the user through the AI Interaction box.",
            "If the user allows it then use expansion_paths to touch uninvolved accounts or tenants outside the named proof scope.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same access-control break reaches cross-tenant or privileged workflows.",
            "Promotion strengthens when the proof expands from one record into bulk read, export, or administrative action impact.",
        ],
    },
    "authentication": {
        "profile_name": "authentication-boundary",
        "baseline_confirmation": "Capture one unauthenticated baseline and one authenticated comparison before broadening the claim.",
        "safe_steps": [
            "Verify the same response path with and without the expected login state or role marker.",
            "Check whether the weakness is limited to one endpoint or persists across adjacent account-management or administrative paths.",
        ],
        "expansion_paths": [
            "Escalate when the same bypass reaches administrative or cross-user data paths.",
            "Escalate when the same missing authentication boundary affects session establishment, recovery, or privileged API routes.",
        ],
        "required_evidence": [
            "A baseline showing the expected authentication boundary and a comparison showing the bypassed path.",
            "A note describing the affected role, endpoint family, and resulting data or action exposure.",
        ],
        "stop_conditions": [
            "Inform about modifying privileged settings, destructive workflows, or real-user account data and ask for permission from the user.",
            "If the user allows it then use expansion_paths to credential guessing, session spraying, or broad account enumeration.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the bypass reaches administrative APIs or sensitive account-management workflows.",
            "Promotion strengthens when the proof shows a stable path to other-user or tenant-level data exposure.",
        ],
    },
    "session-management": {
        "profile_name": "session-state",
        "baseline_confirmation": "Capture one bounded session-state comparison before claiming broader account impact.",
        "safe_steps": [
            "Record the visible session or role marker and compare it to the HTTP session state seen in Burp.",
            "Check whether the weakness is limited to one session transition or affects adjacent account-management workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same weakness crosses user boundaries, session fixation, or privilege-transition paths.",
            "Escalate when the proof shows durable session abuse rather than one ambiguous state mismatch.",
        ],
        "required_evidence": [
            "A note showing the session-state transition, role indicator, or token-handling mismatch.",
            "A comparison proving the same weakness survives re-login, refresh, or role transition.",
        ],
        "stop_conditions": [
            "Ask for permission before hijacking or persisting another user's active session state.",
            "Stop if the next step would create account lockouts or invalidate real-user sessions.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same session flaw crosses user or privilege boundaries.",
            "Promotion strengthens when the weakness persists across re-authentication or account recovery flows.",
        ],
    },
    "xss": {
        "profile_name": "rendering-sink",
        "baseline_confirmation": "Confirm the exact rendering context with one benign proof and record whether any privileged workflow reaches it.",
        "safe_steps": [
            "Confirm whether the sink is HTML, attribute, script, or text context and keep the proof benign.",
            "Check whether the same sink appears in administrative, support, or shared-user workflows before claiming broader impact.",
        ],
        "expansion_paths": [
            "Escalate when the same sink is reachable by higher-privilege users or shared cross-user views.",
            "Escalate when stored reachability, trust boundary, or sensitive workflow reach is confirmed with benign artifacts.",
        ],
        "required_evidence": [
            "One benign rendering artifact that shows the exact sink context.",
            "One note tying the sink to the user role or workflow that can observe it.",
        ],
        "stop_conditions": [
            "Ask before building a weaponized payload chain or touching real-user browser sessions.",
            "Inform them about these harmful content to messaging, payment, or irreversible workflows and ask for permission.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same sink reaches administrative or cross-user workflows.",
            "Promotion strengthens when stored reachability or sensitive session trust implications are confirmed.",
        ],
    },
    "csrf": {
        "profile_name": "state-change-control",
        "baseline_confirmation": "Confirm one low-risk state-changing workflow first, then check whether the same missing control exists on higher-sensitivity actions.",
        "safe_steps": [
            "Keep the proof to one low-risk, reversible action on a permitted test account.",
            "Map whether the same token, origin, or anti-automation assumption is reused across related workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same missing control reaches approval, payment, administrative, or identity workflows.",
            "Escalate when the proof moves from one benign action into broader account-management exposure.",
        ],
        "required_evidence": [
            "A baseline and comparison showing the missing request-origin or anti-CSRF control.",
            "A note identifying the affected workflow family and business effect of the state change.",
        ],
        "stop_conditions": [
            "Ask before touching destructive, financial, messaging, or irreversible account actions.",
            "Inform if the proof would require real-user interaction, spam, or multi-account side effects and proceed only when approved.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same control gap reaches sensitive account-management or administrative workflows.",
            "Promotion strengthens when one bounded proof demonstrates repeatability across multiple state-changing routes.",
        ],
    },
    "ssrf": {
        "profile_name": "server-side-fetch",
        "baseline_confirmation": "Confirm one benign outbound fetch to an approved test endpoint before claiming internal reach or broader network impact.",
        "safe_steps": [
            "Confirm only against approved benign endpoints and document whether the application fetches, resolves, or stores outbound responses.",
            "Check whether the behavior is limited to internet targets or plausibly extends to internal address spaces without probing them.",
        ],
        "expansion_paths": [
            "Escalate when the evidence shows a stronger trust-boundary crossing than one internet fetch.",
            "Escalate when metadata, credential forwarding, or internal service reach is demonstrated within explicit program allowance.",
        ],
        "required_evidence": [
            "One approved callback or benign fetch artifact tied to the exact request path.",
            "A note describing whether the application resolves, follows redirects, stores responses, or reflects metadata.",
        ],
        "stop_conditions": [
            "Ask before internal enumeration, cloud metadata access, or non-approved out-of-band infrastructure.",
            "Ask if the next step would touch third-party systems, internal address space, or destructive backend workflows.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same fetch path reaches internal services, metadata, or credential-bearing requests.",
            "Promotion strengthens when the proof shows repeatable pivot potential rather than one benign internet callback.",
        ],
    },
    "xxe": {
        "profile_name": "xml-parser",
        "baseline_confirmation": "Confirm one bounded XML parser behavior difference before claiming external entity resolution or backend file access.",
        "safe_steps": [
            "Use one benign XML variant that shows parser-controlled behavior without attempting sensitive file or network access.",
            "Check whether the same parser behavior appears across import, preview, or export workflows before escalating impact.",
        ],
        "expansion_paths": [
            "Escalate when the parser resolves external entities or reveals stronger backend trust-boundary crossing.",
            "Escalate when the same parser weakness reaches privileged data import or processing workflows with explicit program allowance.",
        ],
        "required_evidence": [
            "One parser behavior delta tied to a benign XML variant.",
            "A note identifying whether entity resolution, external fetch, or file-read primitives appear to be reachable.",
        ],
        "stop_conditions": [
            "Ask before sensitive file targets, internal network fetches, or non-approved out-of-band endpoints.",
            "Ask if the next step would exceed the saved policy allowance for XML parser testing.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the parser resolves external entities or backend file reads under explicit allowance.",
            "Promotion strengthens when the same weakness crosses into privileged import or document-processing workflows.",
        ],
    },
    "deserialization": {
        "profile_name": "unsafe-deserialization",
        "baseline_confirmation": "Confirm one bounded deserialization behavior change before claiming gadget reach or stronger backend impact.",
        "safe_steps": [
            "Use one benign serialized variant that demonstrates object handling without attempting code execution or state corruption.",
            "Check whether the same object boundary appears across import, background processing, or administrative workflows.",
        ],
        "expansion_paths": [
            "Escalate when object injection reaches privileged workflow state, data exposure, or stronger backend primitives under explicit allowance.",
            "Escalate when the same sink is reusable across multiple handlers or background consumers.",
        ],
        "required_evidence": [
            "One bounded object-handling delta tied to the same request path.",
            "A note describing whether the sink appears reflective, stateful, or delegated to privileged processing.",
        ],
        "stop_conditions": [
            "Ask before gadget experimentation, code-execution paths, or state-corrupting payload chains.",
            "ask if the next step would exceed the saved policy allowance for deserialization testing.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same sink reaches privileged object handling or backend workflow control.",
            "Promotion strengthens when explicit policy allows stronger proof and the evidence shows repeatable sink reachability.",
        ],
    },
    "http-request-smuggling": {
        "profile_name": "request-boundary-desync",
        "baseline_confirmation": "Confirm one bounded parser disagreement or queue-poisoning indicator before claiming broader desync impact.",
        "safe_steps": [
            "Keep the proof limited to one low-noise parser disagreement and observe only safe boundary indicators.",
            "Check whether the behavior is isolated to one route or appears across the same front-end/back-end path pair.",
        ],
        "expansion_paths": [
            "Escalate when the same desync path shows repeatable queue poisoning, route confusion, or credential mix-up within explicit allowance.",
            "Escalate when the parser disagreement affects privileged routes or cross-user response handling.",
        ],
        "required_evidence": [
            "A baseline and comparison showing stable parser disagreement or request-queue side effects.",
            "A note identifying the front-end/back-end boundary or routing behavior involved.",
        ],
        "stop_conditions": [
            "Ask before poisoning live users, causing denial of service, or targeting privileged production traffic flows.",
            "Ask if the next step would exceed explicit program allowance for smuggling or desync testing.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same boundary produces repeatable queue poisoning or cross-user route confusion.",
            "Promotion strengthens when the desync reaches privileged paths under explicit program allowance.",
        ],
    },
    "race-condition": {
        "profile_name": "concurrency-boundary",
        "baseline_confirmation": "Confirm one bounded concurrency window on a reversible test workflow before claiming broader race impact.",
        "safe_steps": [
            "Keep the proof to the smallest allowed concurrency burst and one reversible state transition.",
            "Check whether the same timing issue affects adjacent approval, balance, quota, or role-sensitive workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same timing window crosses into monetary, approval, inventory, or privileged account effects under explicit allowance.",
            "Escalate when the race is repeatable across more than one workflow boundary.",
        ],
        "required_evidence": [
            "A timeline or paired artifact showing the same state transition racing successfully.",
            "A note describing the business effect, rollback behavior, and concurrency assumptions involved.",
        ],
        "stop_conditions": [
            "Ask before causing data corruption, duplicated real-world side effects, or availability impact.",
            "Ask if the next step would exceed explicit program allowance for concurrency or race testing.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the race reaches financial, approval, inventory, or privilege-changing workflows.",
            "Promotion strengthens when the same timing window is repeatable under bounded, low-noise conditions.",
        ],
    },
    "injection": {
        "profile_name": "backend-injection",
        "baseline_confirmation": "Confirm one non-destructive behavioral difference first, then determine whether the same sink exists in higher-privilege workflows.",
        "safe_steps": [
            "Use one benign variant that shows the sink is interpreted rather than echoed or ignored.",
            "Check whether the same parameter or sink exists in reporting, administrative, or cross-tenant workflows to assess impact breadth.",
        ],
        "expansion_paths": [
            "Escalate when the same interpreted sink reaches broader data exposure, workflow manipulation, or privileged surfaces.",
            "Escalate when the sink is repeatable across more than one trusted parameter family.",
        ],
        "required_evidence": [
            "A stable baseline-vs-variant delta showing interpreted behavior.",
            "A note identifying whether the sink is reflective, read-only, state-changing, or privileged.",
        ],
        "stop_conditions": [
            "Ask before destructive queries, file writes, command execution, or data corruption.",
            "Ask if the next step would move from bounded confirmation into weaponized exploit development.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same sink reaches privileged or cross-tenant workflows.",
            "Promotion strengthens when the interpreted behavior reliably exposes data or manipulates trusted backend logic.",
        ],
    },
    "template-injection": {
        "profile_name": "template-evaluation",
        "baseline_confirmation": "Confirm one bounded template-evaluation signal before claiming stronger server-side execution impact.",
        "safe_steps": [
            "Use one benign evaluation marker that shows template interpretation without attempting execution or destructive output.",
            "Check whether the same template sink appears in administrative, preview, or reporting workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same sink reaches privileged rendering workflows or backend-controlled templates.",
            "Escalate when the evaluation surface is repeatable and more than purely reflective.",
        ],
        "required_evidence": [
            "A bounded template-evaluation delta tied to the same rendering path.",
            "A note describing whether the sink is user-facing only or connected to privileged backend rendering.",
        ],
        "stop_conditions": [
            "Ask before execution-oriented payload chains, file access attempts, or destructive server-side actions.",
            "Ask if the next step would exceed bounded confirmation of template evaluation.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when evaluation reaches privileged rendering workflows.",
            "Promotion strengthens when the same sink is repeatable across multiple trusted template surfaces.",
        ],
    },
    "file-upload": {
        "profile_name": "upload-surface",
        "baseline_confirmation": "Confirm one bounded upload-control bypass before claiming stored execution or broader file-handling impact.",
        "safe_steps": [
            "Check whether the application accepts, stores, or serves an unexpected but benign file variant.",
            "Map whether the same upload path reaches administrative preview, processing, or cross-user retrieval workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same upload weakness reaches privileged processing, shared retrieval, or server-side interpretation paths.",
            "Escalate when storage, retrieval, and trust-boundary implications are all confirmed with benign files.",
        ],
        "required_evidence": [
            "A baseline and comparison showing the unexpected file-handling behavior.",
            "A note describing whether the upload is stored, rendered, transformed, or served to other users.",
        ],
        "stop_conditions": [
            "Ask before executable content, malware-like artifacts, or irreversible storage abuse.",
            "Ask if the next step would affect other users or shared processing infrastructure.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same upload path reaches privileged processing or shared retrieval.",
            "Promotion strengthens when benign artifacts show durable trust-boundary crossing beyond one upload acceptance bug.",
        ],
    },
    "file-read": {
        "profile_name": "file-access",
        "baseline_confirmation": "Confirm one bounded file-access or path-handling behavior difference before claiming broader file exposure.",
        "safe_steps": [
            "Use one benign path variant that shows trusted file handling is weaker than expected.",
            "Check whether the same file boundary applies across export, preview, import, or attachment workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same boundary reaches sensitive file classes, cross-user attachments, or privileged backend paths within program rules.",
            "Escalate when the same weakness is repeatable across more than one file-handling workflow.",
        ],
        "required_evidence": [
            "A stable file-handling delta tied to the same request path.",
            "A note describing which file boundary, path rule, or storage scope appears to break.",
        ],
        "stop_conditions": [
            "Ask before sensitive file targets, credential material, or broad filesystem enumeration.",
            "Ask if the next step would exceed bounded file-boundary confirmation.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same weakness reaches sensitive or cross-user file exposure.",
            "Promotion strengthens when the file boundary break is repeatable across multiple trusted workflows.",
        ],
    },
    "open-redirect": {
        "profile_name": "redirect-trust",
        "baseline_confirmation": "Confirm one bounded redirect trust failure before claiming token leakage, phishing, or chained auth impact.",
        "safe_steps": [
            "Verify the redirect target handling with one benign external destination and record the trust indicator involved.",
            "Check whether the same redirect parameter is reused in login, invite, recovery, or OAuth-adjacent workflows.",
        ],
        "expansion_paths": [
            "Escalate when the redirect is embedded in trusted login, invite, recovery, or shared navigation workflows.",
            "Escalate when the same redirect trust failure plausibly carries tokens or security context within program rules.",
        ],
        "required_evidence": [
            "A baseline and comparison showing the application accepts or reflects an untrusted redirect target.",
            "A note describing whether the affected workflow is generic navigation or a trusted auth-adjacent path.",
        ],
        "stop_conditions": [
            "Ask before phishing, token theft, or user-targeted abuse flows.",
            "Ask if the next step would require real-user interaction or off-platform social engineering.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the redirect is embedded in trusted auth or invite workflows.",
            "Promotion strengthens when the proof shows token-bearing or security-sensitive context rather than generic navigation only.",
        ],
    },
    "cors": {
        "profile_name": "cross-origin-trust",
        "baseline_confirmation": "Confirm one bounded cross-origin trust failure before claiming credentialed cross-site data exposure.",
        "safe_steps": [
            "Verify whether the same origin policy weakness is reflective, wildcard, or credentialed with one benign origin.",
            "Check whether the same policy mistake affects sensitive API routes or only low-value endpoints.",
        ],
        "expansion_paths": [
            "Escalate when the same CORS weakness reaches credentialed APIs, cross-user data, or privileged account surfaces.",
            "Escalate when the affected routes expose meaningful data rather than generic metadata.",
        ],
        "required_evidence": [
            "One bounded origin comparison showing the trust decision.",
            "A note describing whether credentials are allowed and what data class the affected route returns.",
        ],
        "stop_conditions": [
            "Ask before real-user browser targeting, data extraction at scale, or multi-origin spray testing.",
            "Ask if the next step would move from bounded policy confirmation into user-targeted abuse.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same weakness reaches credentialed APIs with meaningful user data.",
            "Promotion strengthens when the affected routes are privileged or cross-user rather than low-value metadata.",
        ],
    },
    "mass-assignment": {
        "profile_name": "field-boundary",
        "baseline_confirmation": "Confirm one benign privileged-field acceptance on a test account before claiming broader privilege impact.",
        "safe_steps": [
            "Check whether the same unexpected field is merely accepted, persisted, or actually honored by later workflows.",
            "Map whether the same field boundary weakness affects related create, update, import, or administrative APIs.",
        ],
        "expansion_paths": [
            "Escalate when the same field boundary reaches role, quota, billing, approval, or tenant-control semantics.",
            "Escalate when the same weakness is repeatable across multiple object families or administrative routes.",
        ],
        "required_evidence": [
            "A baseline and one bounded privileged-field variant on a test account.",
            "A note describing whether the field is accepted, persisted, reflected, or honored later.",
        ],
        "stop_conditions": [
            "Ask before setting destructive roles, quotas, billing flags, or irreversible account state.",
            "Ask if the next step would affect uninvolved users or shared tenant configuration.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same field boundary affects privileged roles, approval state, or tenant controls.",
            "Promotion strengthens when the weakness is honored beyond one reflective update response.",
        ],
    },
    "host-header": {
        "profile_name": "host-routing-trust",
        "baseline_confirmation": "Confirm one bounded host-header trust failure before claiming cache poisoning, password reset poisoning, or routing abuse.",
        "safe_steps": [
            "Use one benign host variant that demonstrates trusted host routing or URL generation behavior.",
            "Check whether the same trust failure reaches login, recovery, invite, or cache-facing workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same host trust failure reaches password reset, invite, cache, or cross-user URL generation paths.",
            "Escalate when the trust boundary is repeatable across multiple front-door workflows.",
        ],
        "required_evidence": [
            "A baseline and comparison showing host-dependent behavior or generated URL trust.",
            "A note describing whether the weakness affects routing, generated links, cache keys, or email workflows.",
        ],
        "stop_conditions": [
            "Ask before sending real emails, poisoning shared caches, or affecting real-user recovery flows.",
            "Ask if the next step would require user-targeted abuse or shared infrastructure impact.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same host trust failure reaches password reset or invite workflows.",
            "Promotion strengthens when shared cache or cross-user trust boundaries are confirmed.",
        ],
    },
    "web-cache-poisoning": {
        "profile_name": "cache-trust",
        "baseline_confirmation": "Confirm one bounded cache key or cache response trust failure before claiming cross-user poisoning impact.",
        "safe_steps": [
            "Keep the proof to one benign cache variation and record the cache indicator, key behavior, or downstream reflection.",
            "Check whether the same cache behavior reaches authenticated, shared, or privileged routes.",
        ],
        "expansion_paths": [
            "Escalate when the same cache weakness reaches shared-user, authenticated, or privileged content.",
            "Escalate when the cached response can influence security-sensitive flows without broad traffic impact.",
        ],
        "required_evidence": [
            "A baseline and comparison showing stable cache influence or cache key confusion.",
            "A note describing the affected response class, cache indicator, and user-sharing boundary.",
        ],
        "stop_conditions": [
            "Ask before affecting live shared traffic, long-lived cache entries, or user-visible poisoning at scale.",
            "Ask if the next step would create availability or integrity impact for uninvolved users.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same cache weakness reaches authenticated or shared privileged content.",
            "Promotion strengthens when the influence is stable and repeatable without high-noise traffic manipulation.",
        ],
    },
    "clickjacking": {
        "profile_name": "ui-embedding",
        "baseline_confirmation": "Confirm one bounded UI embedding or frame-control failure before claiming workflow abuse impact.",
        "safe_steps": [
            "Record whether frame protections are absent and whether the affected page is low-risk or security-sensitive.",
            "Check whether the same framing weakness reaches approval, payment, or privileged account-management workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same UI embedding weakness reaches sensitive state-changing workflows.",
            "Escalate when the affected workflow has meaningful user-trust or approval implications within program rules.",
        ],
        "required_evidence": [
            "One bounded framing artifact showing the affected page and control state.",
            "A note describing the impacted workflow and whether it is sensitive or low-risk.",
        ],
        "stop_conditions": [
            "Ask before building deceptive overlays or targeting real-user interactions.",
            "Ask if the next step would move into social engineering or harmful UI abuse.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same framing weakness reaches sensitive state-changing workflows.",
            "Promotion strengthens when the workflow has meaningful trust or approval implications.",
        ],
    },
    "graphql": {
        "profile_name": "graphql-surface",
        "baseline_confirmation": "Confirm one bounded GraphQL trust or schema-control failure before claiming broader API abuse impact.",
        "safe_steps": [
            "Check whether the same weakness is schema exposure, field-level auth, mutation abuse, or rate-control weakness.",
            "Map whether the same broken field boundary affects administrative or cross-user object access paths.",
        ],
        "expansion_paths": [
            "Escalate when the same weakness reaches privileged fields, bulk object traversal, or administrative mutations.",
            "Escalate when the same schema or resolver weakness is repeatable across related object families.",
        ],
        "required_evidence": [
            "A bounded query or mutation comparison tied to the same object family.",
            "A note describing whether the issue is schema exposure, auth failure, or mutation boundary weakness.",
        ],
        "stop_conditions": [
            "Ask before bulk enumeration, destructive mutations, or high-noise query expansion.",
            "Ask if the next step would exceed bounded confirmation of the affected resolver boundary.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same weakness reaches privileged fields or mutations.",
            "Promotion strengthens when one bounded proof demonstrates repeatable cross-user or cross-tenant API abuse.",
        ],
    },
    "business-logic": {
        "profile_name": "workflow-logic",
        "baseline_confirmation": "Confirm one bounded workflow invariant break before claiming broader business-logic abuse impact.",
        "safe_steps": [
            "Define the expected business rule first, then capture one baseline and one minimally changed proof that breaks it.",
            "Check whether the same invariant break affects pricing, quota, approval, sequencing, or role-dependent workflows.",
        ],
        "expansion_paths": [
            "Escalate when the same workflow flaw reaches financial, approval, inventory, or privileged business effects.",
            "Escalate when the same rule break is repeatable across more than one workflow family.",
        ],
        "required_evidence": [
            "A baseline and one bounded proof showing the specific invariant break.",
            "A note describing the expected rule, the observed bypass, and the resulting business effect.",
        ],
        "stop_conditions": [
            "Ask before financial impact, destructive transactions, or irreversible account side effects.",
            "Ask if the next step would exceed one bounded workflow proof on a permitted test path.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same logic break reaches monetary, approval, or privileged workflow effects.",
            "Promotion strengthens when the same invariant break is repeatable across multiple workflow boundaries.",
        ],
    },
    "general": {
        "profile_name": "generic-bounded-proof",
        "baseline_confirmation": "Capture one clean baseline and one minimally changed follow-up request before escalating the impact claim.",
        "safe_steps": [
            "Map whether the observed issue remains local to one request or appears across related workflows, roles, or object classes.",
            "Promote the impact claim only after the evidence shows a wider trust boundary, broader data set, or higher-privilege workflow involvement.",
        ],
        "expansion_paths": [
            "Escalate when the same weakness repeats across adjacent workflows or stronger trust boundaries.",
            "Escalate when the impact moves from one bounded anomaly into consistent data exposure or trusted workflow abuse.",
        ],
        "required_evidence": [
            "One baseline artifact, one comparison artifact, and a concise note describing the security-relevant delta.",
            "A note describing which trust boundary, user role, or workflow assumption appears to break.",
        ],
        "stop_conditions": [
            "Ask before destructive actions, high-noise discovery, or touching uninvolved users or third-party systems.",
            "Ask if the next step cannot be explained as one bounded confirmation of the current hypothesis.",
        ],
        "likely_severity_promotions": [
            "Promotion strengthens when the same issue repeats across stronger trust boundaries or privileged workflows.",
            "Promotion strengthens when the evidence consistently shows meaningful data exposure or trusted workflow abuse.",
        ],
    },
}


def normalize_vuln_class(name: str | None) -> str:
    candidate = (name or "").strip().lower()
    if not candidate:
        return "general"
    return _ALIASES.get(candidate, candidate)


def list_supported_escalation_classes() -> list[str]:
    return sorted(_PROFILES)


def build_escalation_guidance(
    payload_like=None,
    *,
    advisory: dict | None = None,
    selected: dict | None = None,
    dashboard_issue: dict | None = None,
    confirmed_count: int = 0,
) -> dict[str, Any]:
    payload = _to_payload_dict(payload_like)
    advisory = dict(advisory or {})
    selected = dict(selected or {})
    dashboard_issue = dict(dashboard_issue or {})

    vuln_class = _pick_vuln_class(payload, advisory, selected, dashboard_issue)
    profile = deepcopy(_PROFILES.get(vuln_class) or _PROFILES["general"])
    status = (selected.get("status") or "").strip().lower()
    primary_next_action = (advisory.get("primary_next_action") or "").strip()
    confirmation_playbooks = [item for item in (advisory.get("confirmation_playbooks") or []) if isinstance(item, str)]

    baseline_confirmation = primary_next_action or profile["baseline_confirmation"]
    safe_steps = _dedupe(
        [
            "Capture one clean baseline request/response pair and keep the exact issue reference attached to the evidence bundle.",
            "Repeat the same flow with the smallest allowed variable change and diff only the security-relevant fields.",
            *profile.get("safe_steps", []),
            *confirmation_playbooks[:2],
        ]
    )
    required_evidence = _dedupe(profile.get("required_evidence", []))
    expansion_paths = _dedupe(profile.get("expansion_paths", []))
    stop_conditions = _dedupe(profile.get("stop_conditions", []))
    likely_severity_promotions = _dedupe(profile.get("likely_severity_promotions", []))

    if confirmed_count == 0 and status != "confirmed":
        safe_steps.append("Keep the reportability level below a strong impact claim until at least one confirmation step is complete.")
    else:
        safe_steps.append("Translate the confirmed effect into a bounded business-impact statement with the minimum supporting proof needed for reporting.")

    policy_gate = assess_high_risk_escalation_policy(payload, requested_classes=[vuln_class])
    if policy_gate.get("effective_applies", policy_gate.get("applies")) and not policy_gate.get("effective_allowed", policy_gate.get("allowed")):
        baseline_confirmation = "Capture one clean baseline confirmation only until the saved program policy explicitly allows higher-risk escalation."
        safe_steps = _dedupe(
            [
                "Keep the proof bounded to one baseline request and one minimally changed confirmation request.",
                policy_gate.get("effective_reason", policy_gate.get("reason", "")),
            ]
        )
        expansion_paths = []
        stop_conditions = _dedupe([policy_gate.get("effective_reason", policy_gate.get("reason", "")), *stop_conditions])

    escalation_ladder = _dedupe([baseline_confirmation, *safe_steps[:3], *expansion_paths[:2]])
    return {
        "vuln_class": vuln_class,
        "escalation_profile": profile.get("profile_name", "generic-bounded-proof"),
        "baseline_confirmation": baseline_confirmation,
        "safe_vapt_escalation_steps": safe_steps[:8],
        "business_impact_expansion_paths": expansion_paths[:6],
        "required_evidence_for_upgrade": required_evidence[:6],
        "stop_conditions": stop_conditions[:6],
        "likely_severity_promotions": likely_severity_promotions[:6],
        "policy_gate": policy_gate,
        "escalation_ladder": escalation_ladder[:8],
    }


def _pick_vuln_class(payload: dict, advisory: dict, selected: dict, dashboard_issue: dict) -> str:
    selected_class = normalize_vuln_class(selected.get("vuln_class") or "")
    if selected_class != "general":
        return selected_class
    issue_class = normalize_vuln_class(dashboard_issue.get("vuln_hint") or "")
    if issue_class != "general":
        return issue_class
    for item in advisory.get("potential_vulnerabilities") or []:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if text.startswith("[") and "]" in text:
            return normalize_vuln_class(text[1:text.index("]")].strip())
    for item in payload.get("review_scope_include_classes") or []:
        normalized = normalize_vuln_class(item)
        if normalized != "general":
            return normalized
    return "general"


def _dedupe(items: list[str]) -> list[str]:
    result: list[str] = []
    for item in items:
        normalized = (item or "").strip()
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _to_payload_dict(payload_like) -> dict[str, Any]:
    if payload_like is None:
        return {}
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like))
