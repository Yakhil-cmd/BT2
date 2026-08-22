# Q4126: URL logged with token query - viewRun in view.go

## Question
Can the URL handled by `viewRun` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L92) carry a token or session parameter that ends up in the browser history or a printed line?

## Target
- File/function: [pkg/cmd/pr/view/view.go:92](pkg/cmd/pr/view/view.go#L92) - `viewRun`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger the flow that appends credentials to the opened URL.
- Invariant to test: Credentials are never placed in URLs handed to a browser.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the opened URL contains no credential parameters.
