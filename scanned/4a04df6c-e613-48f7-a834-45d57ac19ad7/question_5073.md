# Q5073: unauthenticated fallback on error - NewClientFromHTTP in client.go

## Question
When authentication fails inside `NewClientFromHTTP` in [api/client.go](api/client.go#L29), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [api/client.go:29](api/client.go#L29) - `NewClientFromHTTP`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
