# Q2939: unauthenticated fallback on error - NewCachedHTTPClient in http_client.go

## Question
When authentication fails inside `NewCachedHTTPClient` in [api/http_client.go](api/http_client.go#L133), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [api/http_client.go:133](api/http_client.go#L133) - `NewCachedHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
