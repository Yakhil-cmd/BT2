# Q5780: repo coordinates control the request host - fillPlaceholders in api.go

## Question
Can attacker-published repository coordinates or remotes flowing into `fillPlaceholders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L574) determine the API base URL for an authenticated request?

## Target
- File/function: [pkg/cmd/api/api.go:574](pkg/cmd/api/api.go#L574) - `fillPlaceholders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo/remote whose parsed host becomes the API target while the victim's token is attached.
- Invariant to test: The API base URL comes from the authenticated host configuration only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with hostile coordinates asserting the request URL host.
