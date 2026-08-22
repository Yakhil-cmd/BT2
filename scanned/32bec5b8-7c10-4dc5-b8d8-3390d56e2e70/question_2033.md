# Q2033: remote-initiated forward reaches local services - (CodespacesPortForwarder).createTunnelPort in port_forwarder.go

## Question
Can the tunnel handling in `createTunnelPort` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L133) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:133](internal/codespaces/portforwarder/port_forwarder.go#L133) - `(CodespacesPortForwarder).createTunnelPort`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
