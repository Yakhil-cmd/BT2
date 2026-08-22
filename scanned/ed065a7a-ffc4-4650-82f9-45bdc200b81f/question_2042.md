# Q2042: port forwarding binds a public interface - (invoker).RebuildContainer in invoker.go

## Question
Can `RebuildContainer` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L196) be driven by remote data to bind the forwarded port on a non-loopback interface, exposing the victim's machine or the tunnel to the local network?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:196](internal/codespaces/rpc/invoker.go#L196) - `(invoker).RebuildContainer`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a forwarding configuration requesting 0.0.0.0.
- Invariant to test: Local listeners always bind loopback unless the user explicitly asks.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the bind address is loopback for hostile config.
