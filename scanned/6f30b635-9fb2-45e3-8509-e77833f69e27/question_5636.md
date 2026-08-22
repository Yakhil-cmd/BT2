# Q5636: remote-initiated forward reaches local services - (App).SSH in ssh.go

## Question
Can the tunnel handling in `SSH` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L165) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:165](pkg/cmd/codespace/ssh.go#L165) - `(App).SSH`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
