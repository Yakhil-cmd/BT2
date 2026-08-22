# Q5606: remote-initiated forward reaches local services - visibilityToAccessControlEntries in port_forwarder.go

## Question
Can the tunnel handling in `visibilityToAccessControlEntries` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L380) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:380](internal/codespaces/portforwarder/port_forwarder.go#L380) - `visibilityToAccessControlEntries`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
