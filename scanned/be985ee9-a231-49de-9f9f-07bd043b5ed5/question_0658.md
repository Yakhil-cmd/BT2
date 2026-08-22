# Q0658: connection retried against a fallback host - (App).VSCode in code.go

## Question
On failure, does `VSCode` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L36) retry the connection against a host from the error/response payload?

## Target
- File/function: [pkg/cmd/codespace/code.go:36](pkg/cmd/codespace/code.go#L36) - `(App).VSCode`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
