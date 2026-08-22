# Q4367: cache key omits host or auth identity - NewCachedHTTPClient in http_client.go

## Question
Does the caching in `NewCachedHTTPClient` in [api/http_client.go](api/http_client.go#L133) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [api/http_client.go:133](api/http_client.go#L133) - `NewCachedHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
