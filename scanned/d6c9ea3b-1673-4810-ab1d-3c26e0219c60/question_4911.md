# Q4911: hostile JSON drives a security decision - (API).GetCodespacesPermissionsCheck in api.go

## Question
Does `GetCodespacesPermissionsCheck` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L704) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [internal/codespaces/api/api.go:704](internal/codespaces/api/api.go#L704) - `(API).GetCodespacesPermissionsCheck`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
