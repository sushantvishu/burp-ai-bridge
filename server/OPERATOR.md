# Burp AI Bridge Operator Notes

## Quick start

Serve the API with an env file:

```powershell
python -m server serve --env-file .env.example --host 127.0.0.1 --port 8000
```

On Windows, prefer `python -m server serve` over raw `uvicorn --reload`. The bridge CLI now avoids unstable reload mode by default on Windows and will reuse an already running bridge on the same port instead of crashing on startup.

If a stale listener is still bound to port `8000`, stop it cleanly with:

```powershell
python -m server stop --port 8000
```

If you explicitly want a fresh process in one step:

```powershell
python -m server serve --env-file .env --host 127.0.0.1 --port 8000 --stop-existing
```

If you use Burp Suite Pro with PortSwigger's MCP extension, keep Burp running and set:

```powershell
BURP_MCP_CONTEXT_ENABLED=true
BURP_MCP_SERVER_URL=http://127.0.0.1:9876
BURP_MCP_READ_ONLY_ONLY=true
```

For heavy real-target use, keep MCP as the primary context source and keep privacy defaults strict:

```powershell
MCP_ENABLED=true
BURP_MCP_CONTEXT_ENABLED=true
MODEL_PROVIDER_ORDER=mcp,ollama
PRIVACY_MODE=STRICT
PERSISTENCE_REPLAY_PROTECTION_MODE=hash-raw
```

Recommended local model setup for this repo:

```powershell
OLLAMA_MODEL=llama3.2:3b
OLLAMA_FAST_MODEL=qwen3:1.7b
OLLAMA_DEEP_MODEL=qwen3:8b
OLLAMA_CODE_MODEL=llama3.2:3b
AUTO_MODEL_ROUTING_ENABLED=true
MODEL_PROVIDER_ORDER=mcp,ollama
MODEL_ROUTING_DEEP_SCORE_THRESHOLD=8
MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT=4
INTERNET_REFERENCE_ENRICHMENT_ENABLED=true
INTERNET_REFERENCE_MODE=curated-only
EXECUTION_DEFAULT_MAX_CONCURRENCY=1
BENCHMARK_SNAPSHOT_ENABLED=true
BENCHMARK_SNAPSHOT_MAX_RECORDS=120
```

The bridge now defaults to an MCP-grounded runtime strategy. Use live model switching instead of a Burp-side profile picker:

```powershell
# normal triage
OLLAMA_MODEL=llama3.2:3b
# deeper escalation/report review
OLLAMA_DEEP_MODEL=llama3.1:latest
```

Routing policy on lower-RAM laptops:
- keep scanner-only findings on `OLLAMA_MODEL`
- only promote to `OLLAMA_DEEP_MODEL` when scanner context also includes observed evidence such as a response delta, logger evidence, Collaborator evidence, or an evidence timeline
- reserve `OLLAMA_FAST_MODEL` for low-signal proxy/repeater/intruder-style triage

MCP-only scanner-first path:

```powershell
MODEL_PROVIDER_ORDER=mcp
MCP_ENABLED=true
BURP_MCP_CONTEXT_ENABLED=true
```

The bridge now returns a `model_strategy` block plus a `next_try_matrix` and `reporting_impact_notes` in the advisory, impact, Burp next-action, and Repeater-plan responses. Use those fields as the primary "what to try next" guide when escalating a scanner-marked issue.

Automatic local-model routing is now enabled by default. That means the bridge keeps the lighter local model for routine triage, but promotes scanner-marked, evidence-heavy, or deep-escalation requests to the configured deep model when the local signal is strong enough. Manual runtime model selection still takes precedence over auto-routing.

If your AI client only supports stdio for Burp MCP, extract PortSwigger's packaged proxy and set `BURP_MCP_PROXY_COMMAND` to the Java command that launches it.
Direct Repeater tab creation stays blocked unless you explicitly allow `send_to_repeater` in `BURP_MCP_ALLOWED_CAPABILITIES` or its concrete tool name in `BURP_MCP_ALLOWED_TOOLS`.

Fetch the Burp exporter or macro contract:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/exporter-config
```

Fetch the direct-submit contract for a Burp-side sender or macro:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/direct-submit-config
```

Fetch the Burp companion action config:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/companion-config
```

Fetch the locally installed Ollama tags and the bridge's recommended switch targets for Burp-side settings:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/runtime/model-options
```

Switch the active Ollama model without restarting the Python server:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/runtime/model-selection -Method Post -ContentType application/json -Body '{"model_name":"llama3.1:latest","source":"burp-settings"}'
```

Reset the live override and go back to the configured `OLLAMA_MODEL` from the env file:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/runtime/model-selection -Method Delete
```

`/api/runtime/model-options` is the endpoint the Burp-side AI Bridge settings panel should use when it needs the exact model tag to switch to. `/api/runtime/model-selection` changes the active Ollama model immediately for new analysis requests, without a Python server restart. The Burp-side settings flow no longer exposes a profile picker.

Fetch the bundled Burp companion extension contract and sample file paths:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/companion-extension
```

Fetch the Burp-feature recommendation for the current finding, including the preferred starter BCheck or Bambda pack:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/capability-recommendations -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","target_url":"https://example.com","source_tool":"scanner","use_burp_mcp_context":true}'
```

The returned `starter_assets` block now includes production-oriented starter packs, import order, and README paths under `burp_assets/custom_scan_checks` and `burp_assets/bambda`. If you already have the PortSwigger MCP extension enabled, that is enough for context. Import these Burp assets only when the bridge has already narrowed the issue to one bounded request family.

Ask the bridge for the single best official PortSwigger BCheck for the current finding:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/bchecks/recommend -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","target_url":"https://example.com","source_tool":"scanner","use_burp_mcp_context":true}'
```

Use this order for the BCheck loop:

1. MCP plus Burp Scanner issue
2. AI Bridge recommendation
3. official PortSwigger BChecks catalog suggestion
4. import one selected BCheck into Burp
5. run it only on the exact issue family
6. record whether it helped or stayed noisy

Record the outcome of the one imported official BCheck:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/bchecks/results -Method Post -ContentType application/json -Body '{"target_url":"https://example.com","issue_id":"issue-104","selected_bcheck":{"name":"IDOR Boundary Check","relative_path":"other/auth/idor-boundary.bcheck","source_url":"https://github.com/PortSwigger/BChecks/blob/main/other/auth/idor-boundary.bcheck"},"outcome_label":"useful","notes":"Added one clean authorization-boundary artifact."}'
```

Record whether a custom scan check or Bambda was genuinely useful or noisy on the current target:

```powershell
python -m server asset-feedback --asset-type custom_scan_check --asset-id idor-bola-check --label useful --target-url https://target.example/api/invoices/42 --vuln-class idor --selected-profile mcp-grounded-llama32
```

The bridge now re-ranks starter assets with this target-specific signal and false-positive history.

Inspect the structured local guidance database used to ground methodology, validation, impact, workflow, and payload sequencing:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/kb/guidance-db?vuln_class=idor,xss&style=methodology,validation-impact,workflow-payload"
```

Build the current scanner-aware Repeater plan without opening tabs:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/repeater-plan -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","target_url":"https://example.com","source_tool":"scanner","use_burp_mcp_context":true}'
```

Open the same plan directly in Burp Repeater, one tab per planned variant:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/burp/open-repeater-plan?dispatch=true" -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","target_url":"https://example.com","source_tool":"scanner","use_burp_mcp_context":true}'
```

Score the baseline and returned Repeater responses after you test the opened tabs:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/repeater-diff-score -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","raw_response":"HTTP/1.1 403 Forbidden","baseline_response_text":"HTTP/1.1 403 Forbidden","target_url":"https://example.com","repeater_variant_observations":[{"tab_name":"variant-1","response_text":"HTTP/1.1 200 OK"}]}'
```

Do the same scoring plus workflow refresh and best-next-tab selection in one call:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/repeater-sync -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","baseline_response_text":"HTTP/1.1 403 Forbidden","target_url":"https://example.com","source_tool":"repeater","repeater_variant_observations":[{"tab_name":"variant-1","response_text":"HTTP/1.1 200 OK"}]}'
```

Refresh the full Burp AI Bridge panel state for the selected issue, snapshot, or request:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/burp/panel-state?issue_id=issue-104&snapshot_id=snap-104" -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","target_url":"https://example.com","use_burp_mcp_context":true}'
```

Persist or refresh the issue-centric workflow state for that Burp issue:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/issues/workflow -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","target_url":"https://example.com","repeater_variant_observations":[{"tab_name":"variant-1","response_text":"HTTP/1.1 200 OK"}]}'
```

Ask the bridge for the single best next Repeater tab:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/best-next-tab -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","target_url":"https://example.com"}'
```

Inspect the resolved Burp MCP capability map and blocked tools:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/mcp-capabilities
```

Capture one bounded Burp session snapshot for an analysis job:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/session-snapshot -Method Post -ContentType application/json -Body '{"target_url":"https://example.com","source_tool":"repeater","use_burp_mcp_context":true}'
```

Submit a Burp-originated request directly to the async job flow and have the bridge bind a fresh snapshot first:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/burp/submit-job -Method Post -ContentType application/json -Body '{"raw_request":"GET / HTTP/1.1","target_url":"https://example.com","source_tool":"repeater"}'
```

Use the built-in Burp companion sender for plan open, Repeater sync, or panel refresh:

```powershell
python -m server.burp_direct_sender --mode panel-state --issue-id issue-104 --snapshot-id snap-104 --target-url https://example.com --include-plan --include-companion-actions
```

Load the Burp-side starter templates from:

- `samples/burp/BurpAiBridgePanel.py`
- `samples/burp/BurpAiBridgePanel.java`
- `BURP_COMPANION_EXTENSION.md`
- `BURP_SCANNER_CASE_PLAYBOOK.md`

Print the effective local configuration:

```powershell
python -m server doctor --env-file .env.example --output text
```

List built-in bug bounty policy templates:

```powershell
python -m server policy
```

Show one platform template:

```powershell
python -m server policy hackerone --output text
```

Query recent history:

```powershell
python -m server observe history --base-url http://127.0.0.1:8000 --output json --limit 10
```

Query provider diagnostics:

```powershell
python -m server observe diagnostics --base-url http://127.0.0.1:8000 --output markdown --limit 20
```

Capture a benchmark snapshot and compare before/after rollout metrics:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/runtime/benchmark?limit=120"
```

Read these fields first:

- `rollout_comparison.before.avg_latency_seconds` vs `rollout_comparison.after.avg_latency_seconds`
- `rollout_comparison.before.avg_working_set_kb` vs `rollout_comparison.after.avg_working_set_kb`
- `benchmark_snapshots.comparison.delta.latency_percent`
- `benchmark_snapshots.comparison.delta.working_set_percent`
- `model_matrix.rows`

Query audit events:

```powershell
python -m server observe audit --base-url http://127.0.0.1:8000 --output jsonl --limit 50
```

Import curated accepted or downgraded submission regressions into the local review dataset so the bridge can ground its retrieval and wording on real report outcomes:

```powershell
python -m server review-import --outcome accepted --limit 50
python -m server review-import --outcome downgraded --limit 50
```

Fetch a platform-tuned submission report for a stored job:

```powershell
python -m server report JOB_ID --platform bugcrowd --output markdown
```

Fetch the same report against an explicit stored Burp snapshot bundle:

```powershell
python -m server report JOB_ID --platform bugcrowd --snapshot-id SNAPSHOT_ID --output markdown
```

## Remote access

Observability routes require localhost or an admin token by default.

Use one of:

```powershell
python -m server observe audit --token YOUR_TOKEN --base-url http://HOST:8000
```

or send:

```text
Authorization: Bearer YOUR_TOKEN
```

## Suggested bug bounty workflow

Use MCP-first context plus live model switching instead of profile selection. Keep `llama3.2:3b` active for normal triage and switch to the deeper local model only when the finding already has stronger evidence and deserves a higher-quality escalation or reporting pass.

For the exact Burp Dashboard issue flow, use the dedicated operator playbook in `BURP_SCANNER_CASE_PLAYBOOK.md`. That document defines:

- the case state model
- promotion gates
- exact API endpoints by step
- stop conditions for park or drop decisions
- the default 2-hour operator block

The default runtime strategy is MCP-grounded, so the active small model (default `llama3.2:3b`) relies heavily on Burp MCP context, local KB notes, and curated PortSwigger/GitHub references.
The local guidance database under `guidance_db/` also feeds the advisory flow with Strix-inspired methodology, Shannon-inspired validation and impact logic, and HexStrike-inspired workflow and payload ordering.
Completed Burp-backed runs now also feed a local review dataset and Repeater-variant learning store, partitioned by target host and profile, so repeated work on the same program stays better calibrated than generic synthetic fixtures alone.

Prefer `/api/analyze/jobs` for IDE or Burp-driven runs and use the observability routes to inspect:

- history correlation
- provider fallbacks
- audit traces for one `request_id`

Use `/api/browser/verify-plan` only when you can name the exact allowed browser workflows up front.
It is intended for bounded confirmation of rendering or auth state, not autonomous exploitation.

When Burp MCP context is enabled, the bridge will prefer live Burp proxy history, scanner issues, and project options from the PortSwigger extension before relying on manually pasted context.
The bridge now also maps regex-history, collaborator, repeater-context, and intruder-result capabilities through a read-only policy layer by default.
The runtime health and readiness endpoints now also report whether MCP is truly first in the provider and context order instead of merely enabled by configuration.
With `PRIVACY_MODE=STRICT` and `PERSISTENCE_REPLAY_PROTECTION_MODE=hash-raw`, stored history and snapshots keep stronger replay resistance by default. Optionally set `PERSISTENCE_STORAGE_SEAL_KEY` so persisted JSONL records also carry a tamper-evident seal.
The bridge now also keeps issue-family memory keyed by target partition plus Burp issue ID when available, so official BCheck history and false-positive suppression stay attached to the exact issue family instead of the whole host.
