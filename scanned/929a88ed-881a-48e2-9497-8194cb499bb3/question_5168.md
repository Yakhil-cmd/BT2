# Q5168: Authorization header survives cross-host redirect - forkRun in fork.go

## Question
If a server reached from `forkRun` in [pkg/cmd/repo/fork/fork.go](pkg/cmd/repo/fork/fork.go#L159) answers 30x with a `Location` on a different host, does the Authorization header carrying the victim's token get replayed to that host?

## Target
- File/function: [pkg/cmd/repo/fork/fork.go:159](pkg/cmd/repo/fork/fork.go#L159) - `forkRun`
- Entrypoint: gh repo fork
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Point the victim at a host under attacker control (GHES URL, remote, or asset URL) and redirect to a collector.
- Invariant to test: Auth headers are dropped whenever the redirect target's host differs from the original.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock/httptest test: 302 to another host, assert the second request has no Authorization header.
