# Q4541: Authorization header survives cross-host redirect - fetchCommitSHA in http.go

## Question
If a server reached from `fetchCommitSHA` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L175) answers 30x with a `Location` on a different host, does the Authorization header carrying the victim's token get replayed to that host?

## Target
- File/function: [pkg/cmd/extension/http.go:175](pkg/cmd/extension/http.go#L175) - `fetchCommitSHA`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Point the victim at a host under attacker control (GHES URL, remote, or asset URL) and redirect to a collector.
- Invariant to test: Auth headers are dropped whenever the redirect target's host differs from the original.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock/httptest test: 302 to another host, assert the second request has no Authorization header.
