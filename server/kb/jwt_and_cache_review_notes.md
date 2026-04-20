Title: JWT And Cache Review Notes
Source: https://owasp.org/Top10/2025/ ; https://github.com/riramar/Web-Attack-Cheat-Sheet ; https://github.com/m14r41/PentestingEverything
Tags: jwt, cache, auth, owasp, community

# JWT And Cache Review Notes

## JWT / Token Misuse Signals
- `Authorization: Bearer` headers
- JWT-like three-part token format
- Admin or object-specific requests driven by token claims
- Weak separation between token subject, role, tenant, and target object

## Cache Poisoning / Deception Signals
- Authenticated or personalized GET responses
- Missing explicit cache-control protections
- Static-looking paths, suffixes, or response types mixed with sensitive content
- Header, query, or path variations that could affect cache keys

## Practical Questions
- Does a lower-privilege token still reach the same resources or admin routes?
- Can authenticated content be cached due to path tricks or missing vary/cache-control headers?
