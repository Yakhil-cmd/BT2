# Q3520: codespace token scope reuse - (codespace).displayName in common.go

## Question
Can the per-codespace token obtained in `displayName` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L194) be sent to a host or endpoint derived from the response rather than the tunnel's validated endpoint?

## Target
- File/function: [pkg/cmd/codespace/common.go:194](pkg/cmd/codespace/common.go#L194) - `(codespace).displayName`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return connection metadata pointing at a collector.
- Invariant to test: Session tokens go only to the validated tunnel endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token's destination host.
