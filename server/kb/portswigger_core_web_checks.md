Title: PortSwigger Core Web Checks
Source: https://portswigger.net/web-security
Tags: portswigger, access-control, csrf, cors, xss, xxe, file-upload

# PortSwigger Core Web Checks

## Focus Areas
- Access control and object-level authorization
- Authentication and session handling
- CSRF on browser-driven workflows
- CORS trust boundaries
- Reflected and stored XSS
- File upload handling
- XML parser behavior and XXE

## Signals
- Identifier parameters on authenticated endpoints
- Password forms without obvious anti-CSRF material
- Broad or reflected CORS headers
- Upload workflows using multipart requests
- Query parameters likely to be reflected into HTML
- XML request bodies or SOAP-style traffic

## Validation Approach
- Compare behavior across roles, tenants, and object identifiers
- Inspect session cookie flags and login/session transitions
- Check whether HTML forms carry anti-CSRF state
- Replay with modified Origin, redirect, and object reference values
- Test one reflection or parser hypothesis at a time instead of fuzzing blindly

## Burp Relevance
- Use Repeater for request variants
- Use Proxy/HTTP history for response comparison
- Use manual comparison before heavy automation
