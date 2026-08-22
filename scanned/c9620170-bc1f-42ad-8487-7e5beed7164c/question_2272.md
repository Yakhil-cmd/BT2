# Q2272: hostile JSON drives a security decision - findEndCursor in pagination.go

## Question
Does `findEndCursor` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L26) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [pkg/cmd/api/pagination.go:26](pkg/cmd/api/pagination.go#L26) - `findEndCursor`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
