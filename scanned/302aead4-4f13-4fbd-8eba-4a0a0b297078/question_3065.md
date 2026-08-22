# Q3065: Authorization header survives cross-host redirect - linkedBranchRepoFromURL in develop.go

## Question
If a server reached from `linkedBranchRepoFromURL` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L306) answers 30x with a `Location` on a different host, does the Authorization header carrying the victim's token get replayed to that host?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:306](pkg/cmd/issue/develop/develop.go#L306) - `linkedBranchRepoFromURL`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Point the victim at a host under attacker control (GHES URL, remote, or asset URL) and redirect to a collector.
- Invariant to test: Auth headers are dropped whenever the redirect target's host differs from the original.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock/httptest test: 302 to another host, assert the second request has no Authorization header.
