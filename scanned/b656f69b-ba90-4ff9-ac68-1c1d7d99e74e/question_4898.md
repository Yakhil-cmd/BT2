# Q4898: codespace token scope reuse - (invoker).StartSSHServerWithOptions in invoker.go

## Question
Can the per-codespace token obtained in `StartSSHServerWithOptions` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L221) be sent to a host or endpoint derived from the response rather than the tunnel's validated endpoint?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:221](internal/codespaces/rpc/invoker.go#L221) - `(invoker).StartSSHServerWithOptions`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return connection metadata pointing at a collector.
- Invariant to test: Session tokens go only to the validated tunnel endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token's destination host.
