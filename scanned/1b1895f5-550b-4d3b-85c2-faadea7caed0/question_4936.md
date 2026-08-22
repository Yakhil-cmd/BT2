# Q4936: host key / SSH endpoint from the API response - (App).parsePortVisibilities in ports.go

## Question
Does `parsePortVisibilities` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L282) take the SSH destination, port, or connection parameters from a response object that an unprivileged attacker can own (their codespace, their org-less repo) and connect with the victim's credentials?

## Target
- File/function: [pkg/cmd/codespace/ports.go:282](pkg/cmd/codespace/ports.go#L282) - `(App).parsePortVisibilities`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish/share a codespace whose connection metadata targets an attacker host.
- Invariant to test: Connection targets are validated against the authenticated host and expected tunnel domain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the dialed endpoint for hostile metadata.
