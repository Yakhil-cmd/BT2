# Q2227: client reuse leaks headers across hosts - AddAuthTokenHeader in http_client.go

## Question
Does `AddAuthTokenHeader` in [api/http_client.go](api/http_client.go#L152) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [api/http_client.go:152](api/http_client.go#L152) - `AddAuthTokenHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
