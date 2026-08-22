# Q2092: remote-initiated forward reaches local services - (codespace).displayName in common.go

## Question
Can the tunnel handling in `displayName` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L194) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [pkg/cmd/codespace/common.go:194](pkg/cmd/codespace/common.go#L194) - `(codespace).displayName`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
