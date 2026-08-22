# Q0839: repo coordinates control the request host - processResponse in api.go

## Question
Can attacker-published repository coordinates or remotes flowing into `processResponse` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L473) determine the API base URL for an authenticated request?

## Target
- File/function: [pkg/cmd/api/api.go:473](pkg/cmd/api/api.go#L473) - `processResponse`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo/remote whose parsed host becomes the API target while the victim's token is attached.
- Invariant to test: The API base URL comes from the authenticated host configuration only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with hostile coordinates asserting the request URL host.
