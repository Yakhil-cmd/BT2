# Q0656: codespace token scope reuse - getPortPairs in ports.go

## Question
Can the per-codespace token obtained in `getPortPairs` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L372) be sent to a host or endpoint derived from the response rather than the tunnel's validated endpoint?

## Target
- File/function: [pkg/cmd/codespace/ports.go:372](pkg/cmd/codespace/ports.go#L372) - `getPortPairs`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return connection metadata pointing at a collector.
- Invariant to test: Session tokens go only to the validated tunnel endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token's destination host.
