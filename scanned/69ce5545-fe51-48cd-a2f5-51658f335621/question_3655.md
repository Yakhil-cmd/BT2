# Q3655: repo coordinates control the request host - AddAuthTokenHeader in http_client.go

## Question
Can attacker-published repository coordinates or remotes flowing into `AddAuthTokenHeader` in [api/http_client.go](api/http_client.go#L152) determine the API base URL for an authenticated request?

## Target
- File/function: [api/http_client.go:152](api/http_client.go#L152) - `AddAuthTokenHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo/remote whose parsed host becomes the API target while the victim's token is attached.
- Invariant to test: The API base URL comes from the authenticated host configuration only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with hostile coordinates asserting the request URL host.
