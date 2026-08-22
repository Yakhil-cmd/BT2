# Q2090: codespace token scope reuse - (App).RunWithProgress in common.go

## Question
Can the per-codespace token obtained in `RunWithProgress` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L63) be sent to a host or endpoint derived from the response rather than the tunnel's validated endpoint?

## Target
- File/function: [pkg/cmd/codespace/common.go:63](pkg/cmd/codespace/common.go#L63) - `(App).RunWithProgress`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return connection metadata pointing at a collector.
- Invariant to test: Session tokens go only to the validated tunnel endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token's destination host.
