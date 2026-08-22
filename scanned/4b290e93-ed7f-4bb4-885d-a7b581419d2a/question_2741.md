# Q2741: codespace token scope reuse - (CodespaceConnection).Connect in connection.go

## Question
Can the per-codespace token obtained in `Connect` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L89) be sent to a host or endpoint derived from the response rather than the tunnel's validated endpoint?

## Target
- File/function: [internal/codespaces/connection/connection.go:89](internal/codespaces/connection/connection.go#L89) - `(CodespaceConnection).Connect`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return connection metadata pointing at a collector.
- Invariant to test: Session tokens go only to the validated tunnel endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token's destination host.
