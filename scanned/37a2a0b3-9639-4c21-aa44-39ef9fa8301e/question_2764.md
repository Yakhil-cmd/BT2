# Q2764: unauthenticated fallback on error - (API).ListCodespaces in api.go

## Question
When authentication fails inside `ListCodespaces` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L369), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [internal/codespaces/api/api.go:369](internal/codespaces/api/api.go#L369) - `(API).ListCodespaces`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
