# Q0508: Authorization header survives cross-host redirect - GistIDFromURL in shared.go

## Question
If a server reached from `GistIDFromURL` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L84) answers 30x with a `Location` on a different host, does the Authorization header carrying the victim's token get replayed to that host?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:84](pkg/cmd/gist/shared/shared.go#L84) - `GistIDFromURL`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Point the victim at a host under attacker control (GHES URL, remote, or asset URL) and redirect to a collector.
- Invariant to test: Auth headers are dropped whenever the redirect target's host differs from the original.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock/httptest test: 302 to another host, assert the second request has no Authorization header.
