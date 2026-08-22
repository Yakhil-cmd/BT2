# Q4211: connection retried against a fallback host - selectSSHKeys in ssh.go

## Question
On failure, does `selectSSHKeys` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L323) retry the connection against a host from the error/response payload?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:323](pkg/cmd/codespace/ssh.go#L323) - `selectSSHKeys`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
