# Q3514: Authorization header survives cross-host redirect - (App).VSCode in code.go

## Question
If a server reached from `VSCode` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L36) answers 30x with a `Location` on a different host, does the Authorization header carrying the victim's token get replayed to that host?

## Target
- File/function: [pkg/cmd/codespace/code.go:36](pkg/cmd/codespace/code.go#L36) - `(App).VSCode`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Point the victim at a host under attacker control (GHES URL, remote, or asset URL) and redirect to a collector.
- Invariant to test: Auth headers are dropped whenever the redirect target's host differs from the original.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock/httptest test: 302 to another host, assert the second request has no Authorization header.
