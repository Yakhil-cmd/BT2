# Q2016: URL logged with token query - New in browser.go

## Question
Can the URL handled by `New` in [internal/browser/browser.go](internal/browser/browser.go#L13) carry a token or session parameter that ends up in the browser history or a printed line?

## Target
- File/function: [internal/browser/browser.go:13](internal/browser/browser.go#L13) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger the flow that appends credentials to the opened URL.
- Invariant to test: Credentials are never placed in URLs handed to a browser.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the opened URL contains no credential parameters.
