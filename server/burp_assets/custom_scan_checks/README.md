# Custom Scan Checks

These BChecks are meant to be imported only after the bridge and MCP context have already identified a bounded request family.

Use them this way:

1. Pick the pack that matches the current vuln class from the bridge recommendation.
2. Scope it to the exact host and route family already under review.
3. Prefer passive packs first.
4. For bounded-active packs such as SSRF callback confirmation, stop after one correlatable proof artifact.

This directory is not a broad scanner replacement. It is a low-noise operator aid for manual bug bounty follow-up.
