# Q4901: Authorization header survives cross-host redirect - isJupyterServerURLValid in invoker.go

## Question
If a server reached from `isJupyterServerURLValid` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L321) answers 30x with a `Location` on a different host, does the Authorization header carrying the victim's token get replayed to that host?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:321](internal/codespaces/rpc/invoker.go#L321) - `isJupyterServerURLValid`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Point the victim at a host under attacker control (GHES URL, remote, or asset URL) and redirect to a collector.
- Invariant to test: Auth headers are dropped whenever the redirect target's host differs from the original.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock/httptest test: 302 to another host, assert the second request has no Authorization header.
