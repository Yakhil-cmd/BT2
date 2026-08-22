# Q3405: client reuse leaks headers across hosts - DisplayURL in text.go

## Question
Does `DisplayURL` in [internal/text/text.go](internal/text/text.go#L71) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [internal/text/text.go:71](internal/text/text.go#L71) - `DisplayURL`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
