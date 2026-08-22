# Q2082: remote-initiated forward reaches local services - newPortsForwardCmd in ports.go

## Question
Can the tunnel handling in `newPortsForwardCmd` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L301) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [pkg/cmd/codespace/ports.go:301](pkg/cmd/codespace/ports.go#L301) - `newPortsForwardCmd`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
