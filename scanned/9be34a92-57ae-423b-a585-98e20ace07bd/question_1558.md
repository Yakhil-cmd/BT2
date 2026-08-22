# Q1558: Authorization header survives cross-host redirect - findEndCursor in pagination.go

## Question
If a server reached from `findEndCursor` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L26) answers 30x with a `Location` on a different host, does the Authorization header carrying the victim's token get replayed to that host?

## Target
- File/function: [pkg/cmd/api/pagination.go:26](pkg/cmd/api/pagination.go#L26) - `findEndCursor`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Point the victim at a host under attacker control (GHES URL, remote, or asset URL) and redirect to a collector.
- Invariant to test: Auth headers are dropped whenever the redirect target's host differs from the original.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock/httptest test: 302 to another host, assert the second request has no Authorization header.
