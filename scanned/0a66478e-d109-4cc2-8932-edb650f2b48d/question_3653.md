# Q3653: host-scoped client leaked into another flow - NewCachedHTTPClient in http_client.go

## Question
Can the client/transport constructed in `NewCachedHTTPClient` in [api/http_client.go](api/http_client.go#L133) (with its auth round-tripper) be reused by a later flow whose target host came from a repo/remote/host string or API response field the attacker publishes?

## Target
- File/function: [api/http_client.go:133](api/http_client.go#L133) - `NewCachedHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
