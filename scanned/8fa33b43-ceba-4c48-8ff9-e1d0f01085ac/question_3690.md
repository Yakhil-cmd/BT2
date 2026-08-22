# Q3690: DNS rebinding between check and connect - extensionManager in default.go

## Question
Does `extensionManager` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L272) validate a hostname and then dial it later, allowing a rebinding attacker to pass the check and serve a different address?

## Target
- File/function: [pkg/cmd/factory/default.go:272](pkg/cmd/factory/default.go#L272) - `extensionManager`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Serve a short-TTL record that flips after validation.
- Invariant to test: Validation is host-based and enforced at dial time by the same transport.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting validation happens in the transport, not only before it.
