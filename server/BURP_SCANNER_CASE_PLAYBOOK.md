# Burp Scanner Case Playbook

This playbook is the default operating model for Burp Suite Pro scanner issues that are already marked in Burp Dashboard and then sent to AI Bridge.

The goal is not to rediscover the issue. The goal is to decide whether the selected issue is:

- worth bounded confirmation
- worth promotion to a deeper pass
- worth reporting now
- worth parking or dropping

## Case model

Each Burp scanner issue becomes one case with one of these states:

- `anchored`
- `confirming`
- `promoted`
- `reported`
- `parked`
- `dropped`

Use one case at a time. Do not broaden the workflow until the current case either promotes or dies.

## Preconditions

Before using this flow:

- Burp MCP context should be enabled.
- The selected Burp issue should include the exact request if possible.
- `source_tool` should be `scanner` on intake.
- Keep `EXECUTION_DEFAULT_MAX_CONCURRENCY=1` on a 16GB laptop.
- Keep the live advisory path MCP-only and preserve the Burp anchor for promoted cases.

## Exact workflow

### 1. Anchor the case

Select one Burp Dashboard issue and send it to AI Bridge.

Preferred endpoint:

- `POST /api/burp/submit-job`

Required payload shape:

- `raw_request`
- `target_url`
- `source_tool=scanner`
- `use_burp_mcp_context=true`
- `burp_dashboard_issue`

Outcome:

- one async analysis job
- one scanner issue becomes one anchored case

### 2. Read the first bounded advisory

Wait for the job and fetch:

- `GET /api/analyze/jobs/{job_id}`

Read these fields first:

- `primary_next_action`
- `request_plan`
- `potential_vulnerabilities`
- `model_strategy`
- `provider_failover`

If the result is only generic scanner restatement with no bounded next step, do not broaden testing. Refresh panel state and work from the issue workflow instead.

### 3. Refresh the issue control surface

Fetch:

- `POST /api/burp/panel-state`

Use query parameters when available:

- `issue_id`
- `snapshot_id`
- `workflow_id`

Read these fields first:

- `workflow_status`
- `diff_summary`
- `best_next_tab`
- `workflow.report_readiness`
- `notes`

This endpoint is the operator control surface for the case. Prefer it over raw model text.

### 4. Build a bounded confirmation plan

Build the Repeater plan:

- `POST /api/burp/repeater-plan`

Open the plan:

- `POST /api/burp/open-repeater-plan?dispatch=true`

Expected tab shape:

- `1` untouched baseline tab
- `1-3` bounded confirmation tabs

Do not allow broad fuzzing here. A scanner-marked case should first prove one clean boundary or one clean diff.

### 5. Test only the opened tabs

In Burp Repeater:

1. Send the untouched baseline tab first.
2. Send each generated confirmation tab once.
3. Do not add more variants until the current ones are scored.

### 6. Sync and score the confirmation step

After responses exist, call:

- `POST /api/burp/repeater-sync`

This is the primary promotion gate for the case.

Read these fields first:

- `diff.best_item`
- `workflow.status`
- `best_next_tab`
- `summary`

## Promotion gates

Promote the case from `confirming` to `promoted` only if one or more of these are true:

- `diff.best_item.score >= 2.5`
- stable auth boundary change such as `401 -> 200` or `403 -> 200`
- stable object or tenant crossover on a controlled variant
- collaborator or callback evidence matches the same request family
- bounded workflow inconsistency repeats cleanly
- `workflow.status` becomes `high-signal-delta`

If none of those happen, do not invoke the deeper pass.

## Deeper pass rules

Use the deeper MCP-backed pass only after promotion.

Allowed deeper pass triggers:

- promoted scanner case with a clean best diff
- promoted case with reportability ambiguity
- promoted case with multiple coherent escalation paths

Do not use deeper reasoning for:

- passive scanner noise
- weak informational findings
- cases with no clean manual delta
- repeated no-signal Repeater cycles

## Validation and impact gates

For promoted cases, call:

- `POST /api/hypotheses/validate`
- `POST /api/impact/rank`
- optionally `POST /api/impact/upgrade-plan`

Move to `reported` only when:

- the validation result is no longer just scanner wording
- the impact path matches the evidence you actually have
- the reportability gate is not blocked
- the next step is packaging, not more searching

## Stop conditions

Park or drop the case when any of these are true:

- no new signal after `2` Repeater sync cycles
- the strongest observation repeats with no new evidence
- only scanner-generated wording exists and no clean manual delta exists
- scope or policy gate blocks safe expansion
- the evidence is too weak to support the claim

Use:

- `parked` for maybe-later cases with some structure but not enough proof
- `dropped` for clear noise or non-actionable cases

## Reporting path

Once the case is promoted and validated, stop exploring and package evidence.

Use:

- `GET /api/history/jobs/{job_id}/evidence-bundle`
- `GET /api/history/jobs/{job_id}/submission-report`

Read these first:

- report title
- evidence bundle
- impact statement
- reproduction steps
- reportability gate notes

## Daily routine

Use this as the default 2-hour operating block.

### 0 to 20 minutes

- Select `3-5` Burp Dashboard issues.
- Send each as a separate case with `POST /api/burp/submit-job`.
- Drop obvious low-value informational noise immediately.

### 20 to 60 minutes

- Review `GET /api/analyze/jobs/{job_id}` and `POST /api/burp/panel-state`.
- Keep only the top `1-2` anchored cases.
- Build Repeater plans for those cases only.

### 60 to 100 minutes

- Run `POST /api/burp/open-repeater-plan?dispatch=true`.
- Test only the generated tabs.
- Score and refresh with `POST /api/burp/repeater-sync`.

### 100 to 120 minutes

- Promote one case to validation and reporting
- or park/drop all remaining cases cleanly

Do not finish the block with a large pile of unscored cases.

## Real-world priorities

When multiple Burp scanner issues are available, prefer this order:

1. access control and IDOR/BOLA
2. authentication boundary issues
3. SSRF and callback-capable issues
4. business logic and workflow abuse
5. race-condition candidates with bounded evidence
6. stored rendering issues with admin or reviewer path
7. passive informational findings only if they improve another active case

## Hard rules

- One selected Burp issue equals one case.
- Repeater confirmation comes before broader exploration.
- Deep reasoning is earned, not default.
- Reporting starts as soon as evidence is clean enough.
- If the case stops improving, park or drop it.
