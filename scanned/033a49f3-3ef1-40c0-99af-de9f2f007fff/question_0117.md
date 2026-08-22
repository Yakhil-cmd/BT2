# Q0117: repo coordinates control the request host - newBrowser in default.go

## Question
Can attacker-published repository coordinates or remotes flowing into `newBrowser` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L251) determine the API base URL for an authenticated request?

## Target
- File/function: [pkg/cmd/factory/default.go:251](pkg/cmd/factory/default.go#L251) - `newBrowser`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo/remote whose parsed host becomes the API target while the victim's token is attached.
- Invariant to test: The API base URL comes from the authenticated host configuration only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with hostile coordinates asserting the request URL host.
