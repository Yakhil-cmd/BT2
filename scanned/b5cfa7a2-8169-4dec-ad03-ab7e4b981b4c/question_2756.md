# Q2756: remote-initiated forward reaches local services - (invoker).RebuildContainer in invoker.go

## Question
Can the tunnel handling in `RebuildContainer` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L196) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:196](internal/codespaces/rpc/invoker.go#L196) - `(invoker).RebuildContainer`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
