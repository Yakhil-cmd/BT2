# Q3124: URL logged with token query - NewCmdRoot in root.go

## Question
Can the URL handled by `NewCmdRoot` in [pkg/cmd/root/root.go](pkg/cmd/root/root.go#L64) carry a token or session parameter that ends up in the browser history or a printed line?

## Target
- File/function: [pkg/cmd/root/root.go:64](pkg/cmd/root/root.go#L64) - `NewCmdRoot`
- Entrypoint: gh root root
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Trigger the flow that appends credentials to the opened URL.
- Invariant to test: Credentials are never placed in URLs handed to a browser.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the opened URL contains no credential parameters.
