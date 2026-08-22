# Q1313: remote-initiated forward reaches local services - (CodespaceConnection).Connect in connection.go

## Question
Can the tunnel handling in `Connect` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L89) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [internal/codespaces/connection/connection.go:89](internal/codespaces/connection/connection.go#L89) - `(CodespaceConnection).Connect`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
