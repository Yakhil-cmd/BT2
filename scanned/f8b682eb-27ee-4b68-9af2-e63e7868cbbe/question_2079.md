# Q2079: codespace token scope reuse - getDevContainer in ports.go

## Question
Can the per-codespace token obtained in `getDevContainer` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L188) be sent to a host or endpoint derived from the response rather than the tunnel's validated endpoint?

## Target
- File/function: [pkg/cmd/codespace/ports.go:188](pkg/cmd/codespace/ports.go#L188) - `getDevContainer`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return connection metadata pointing at a collector.
- Invariant to test: Session tokens go only to the validated tunnel endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token's destination host.
