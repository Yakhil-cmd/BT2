# Q1006: hostile JSON drives a security decision - Parse in frontmatter.go

## Question
Does `Parse` in [internal/skills/frontmatter/frontmatter.go](internal/skills/frontmatter/frontmatter.go#L31) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [internal/skills/frontmatter/frontmatter.go:31](internal/skills/frontmatter/frontmatter.go#L31) - `Parse`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
