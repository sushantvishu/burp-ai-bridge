Title: OWASP Top 10 2025 Notes
Source: https://owasp.org/Top10/2025/
Tags: owasp, top10, 2025, classification

# OWASP Top 10 2025 Notes

## Top 10 2025 Categories Relevant To This Project
- A01 Broken Access Control
- A02 Security Misconfiguration
- A04 Cryptographic Failures
- A05 Injection
- A06 Insecure Design
- A07 Authentication Failures
- A08 Software or Data Integrity Failures
- A10 Mishandling of Exceptional Conditions

## Practical Mapping For Burp AI Bridge
- Access control, IDOR, and admin-path issues map well to A01
- Missing headers, weak cache behavior, and permissive CORS often map to A02
- SQLi, command injection, and XXE map to A05
- JWT misuse and weak token trust boundaries often map to A07 or A08 depending on the failure mode
- Business logic and workflow abuse often reflect A06 Insecure Design
- Verbose backend errors often support A10 Mishandling of Exceptional Conditions

## Usage Guidance
- Use Top 10 2025 for high-level classification
- Use WSTG for concrete testing steps
- Use PortSwigger and HackTricks for practical hypotheses and bypass ideas
