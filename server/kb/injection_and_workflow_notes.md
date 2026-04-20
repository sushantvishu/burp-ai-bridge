Title: Injection And Workflow Review Notes
Source: https://owasp.org/www-project-web-security-testing-guide/v42/ ; https://github.com/EdOverflow/bugbounty-cheatsheet/tree/master/cheatsheets ; https://github.com/m14r41/PentestingEverything
Tags: sqli, command-injection, business-logic, owasp, community

# Injection And Workflow Review Notes

## SQL Injection Signals
- Query, search, sort, filter, and identifier parameters
- Error-like database strings in responses
- Timing or boolean-sensitive behavior after small input mutations

## Command Injection Signals
- Endpoints that appear to run diagnostics, import/export, conversions, or network fetches
- Error patterns suggesting backend process execution or shell parsing

## Business Logic Signals
- Multi-step flows such as checkout, transfer, approval, coupon, password reset, or redemption
- Client-controlled quantity, amount, state, or sequencing values
- Replays or reordered requests that still succeed

## Burp Workflow Guidance
- Test one parameter or one workflow assumption at a time
- Compare status, length, timing, and semantic output
- Group results by vulnerability class before expanding scope
