# Q0651: remote-initiated forward reaches local services - getDevContainer in ports.go

## Question
Can the tunnel handling in `getDevContainer` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L188) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [pkg/cmd/codespace/ports.go:188](pkg/cmd/codespace/ports.go#L188) - `getDevContainer`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
