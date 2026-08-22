# Q2273: repo coordinates control the request host - (paginatedArrayReader).Read in pagination.go

## Question
Can attacker-published repository coordinates or remotes flowing into `Read` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L123) determine the API base URL for an authenticated request?

## Target
- File/function: [pkg/cmd/api/pagination.go:123](pkg/cmd/api/pagination.go#L123) - `(paginatedArrayReader).Read`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo/remote whose parsed host becomes the API target while the victim's token is attached.
- Invariant to test: The API base URL comes from the authenticated host configuration only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with hostile coordinates asserting the request URL host.
