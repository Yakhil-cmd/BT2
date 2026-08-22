# Q5632: remote-initiated forward reaches local services - (API).GetCodespaceRepositoryContents in api.go

## Question
Can the tunnel handling in `GetCodespaceRepositoryContents` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1227) accept a reverse/remote-initiated forward, letting the codespace side reach services on the victim's workstation?

## Target
- File/function: [internal/codespaces/api/api.go:1227](internal/codespaces/api/api.go#L1227) - `(API).GetCodespaceRepositoryContents`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Request the forward from the codespace side.
- Invariant to test: Only locally initiated forwards to codespace ports are honoured.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting remote-initiated forward requests are rejected.
