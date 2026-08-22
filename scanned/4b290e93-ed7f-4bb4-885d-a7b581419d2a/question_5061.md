# Q5061: unauthenticated fallback on error - GetCurrentLogin in login_flow.go

## Question
When authentication fails inside `GetCurrentLogin` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L253), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:253](pkg/cmd/auth/shared/login_flow.go#L253) - `GetCurrentLogin`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
