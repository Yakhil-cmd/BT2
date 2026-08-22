# Q4917: codespace token scope reuse - (API).ListDevContainers in api.go

## Question
Can the per-codespace token obtained in `ListDevContainers` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1093) be sent to a host or endpoint derived from the response rather than the tunnel's validated endpoint?

## Target
- File/function: [internal/codespaces/api/api.go:1093](internal/codespaces/api/api.go#L1093) - `(API).ListDevContainers`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return connection metadata pointing at a collector.
- Invariant to test: Session tokens go only to the validated tunnel endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token's destination host.
