# Q1379: host key / SSH endpoint from the API response - (codespace).running in common.go

## Question
Does `running` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L231) take the SSH destination, port, or connection parameters from a response object that an unprivileged attacker can own (their codespace, their org-less repo) and connect with the victim's credentials?

## Target
- File/function: [pkg/cmd/codespace/common.go:231](pkg/cmd/codespace/common.go#L231) - `(codespace).running`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish/share a codespace whose connection metadata targets an attacker host.
- Invariant to test: Connection targets are validated against the authenticated host and expected tunnel domain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the dialed endpoint for hostile metadata.
