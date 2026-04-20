Title: Authorization Bypass Template
Source: manual
Tags: auth-bypass, idor, access-control

# Authorization Bypass / IDOR Template

## Signals
- Identifier-like parameters such as `id`, `userId`, `accountId`, `tenantId`
- Admin or management paths
- Authenticated request succeeds with weak object scoping

## Validation Approach
- Replay the same request with another user's identifier while keeping the same session.
- Compare unauthenticated, low-privilege, and higher-privilege responses.
- Look for differences in status code, response body shape, and record ownership checks.

## Good Questions
- Is the identifier sequential or easily discoverable?
- Are object references leaked in other endpoints, mobile responses, or logs?
- Does the response change only cosmetically, or is access actually blocked?

## Tooling Hints
- nuclei tags: `idor,auth-bypass,api`
- wordlists: parameter names and object identifiers gathered from traffic
