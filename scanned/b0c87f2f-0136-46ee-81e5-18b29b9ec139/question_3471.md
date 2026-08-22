# Q3471: remote-initiated forward reaches local services - (invoker).StartSSHServerWithOptions in invoker.go

## Question
Can the tunnel handling in `StartSSHServerWithOptions` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L221) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:221](internal/codespaces/rpc/invoker.go#L221) - `(invoker).StartSSHServerWithOptions`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
