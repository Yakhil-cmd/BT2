# Q2937: scope/permission check bypass - NewHTTPClient in http_client.go

## Question
Does `NewHTTPClient` in [api/http_client.go](api/http_client.go#L33) make a security decision from a scope/permission value returned by the server (or absent header) that a repo/remote/host string or API response field the attacker publishes can influence?

## Target
- File/function: [api/http_client.go:33](api/http_client.go#L33) - `NewHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
