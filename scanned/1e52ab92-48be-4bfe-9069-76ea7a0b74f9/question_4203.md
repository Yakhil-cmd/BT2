# Q4203: unauthenticated fallback on error - (API).DeleteCodespace in api.go

## Question
When authentication fails inside `DeleteCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1051), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [internal/codespaces/api/api.go:1051](internal/codespaces/api/api.go#L1051) - `(API).DeleteCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
