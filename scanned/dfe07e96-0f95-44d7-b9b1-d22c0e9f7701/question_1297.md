# Q1297: URL logged with token query - NewCmdBrowse in browse.go

## Question
Can the URL handled by `NewCmdBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L52) carry a token or session parameter that ends up in the browser history or a printed line?

## Target
- File/function: [pkg/cmd/browse/browse.go:52](pkg/cmd/browse/browse.go#L52) - `NewCmdBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger the flow that appends credentials to the opened URL.
- Invariant to test: Credentials are never placed in URLs handed to a browser.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the opened URL contains no credential parameters.
