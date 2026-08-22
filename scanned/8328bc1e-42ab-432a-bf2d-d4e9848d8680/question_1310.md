# Q1310: remote-initiated forward reaches local services - waitUntilCodespaceConnectionReady in codespaces.go

## Question
Can the tunnel handling in `waitUntilCodespaceConnectionReady` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L78) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [internal/codespaces/codespaces.go:78](internal/codespaces/codespaces.go#L78) - `waitUntilCodespaceConnectionReady`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
