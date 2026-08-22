# Q1030: hostile JSON drives a security decision - fetchDescription in discovery.go

## Question
Does `fetchDescription` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L648) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [internal/skills/discovery/discovery.go:648](internal/skills/discovery/discovery.go#L648) - `fetchDescription`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
