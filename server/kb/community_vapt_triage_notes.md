Title: Community VAPT Triage Notes
Source: https://github.com/EdOverflow/bugbounty-cheatsheet/tree/master/cheatsheets ; https://github.com/riramar/Web-Attack-Cheat-Sheet ; https://github.com/m14r41/PentestingEverything ; https://github.com/psydck-pysdck/Handbook/tree/main/VAPT
Tags: community, vapt, triage, bugbounty, mobile-api

# Community VAPT Triage Notes

## Useful Community Themes
- Start from trust boundaries: auth, session, redirects, URL fetches, uploads, parsers
- Prefer categorized checklists over vague “scan everything” prompts
- Treat mobile app traffic as API security unless you have device/runtime context
- Keep findings grouped by vuln class so review is easier

## Good Burp-Facing Categories
- Access control / IDOR / BOLA
- Authentication and token scope
- Session management and cookie hardening
- CORS and browser trust
- Reflected input and XSS review
- SSRF / URL fetch behavior
- File upload handling
- XML / XXE / parser abuse
- Information disclosure and verbose errors

## Workflow Guidance
- Compare variants manually before escalating to heavy tooling
- Use one endpoint or one hypothesis at a time on slow local analysis
- Capture operator answers such as role, rate limit, and trust boundaries early
