# Q4261: Authorization header survives cross-host redirect - NewCmdSet in set.go

## Question
If a server reached from `NewCmdSet` in [pkg/cmd/alias/set/set.go](pkg/cmd/alias/set/set.go#L29) answers 30x with a `Location` on a different host, does the Authorization header carrying the victim's token get replayed to that host?

## Target
- File/function: [pkg/cmd/alias/set/set.go:29](pkg/cmd/alias/set/set.go#L29) - `NewCmdSet`
- Entrypoint: gh alias set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Point the victim at a host under attacker control (GHES URL, remote, or asset URL) and redirect to a collector.
- Invariant to test: Auth headers are dropped whenever the redirect target's host differs from the original.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock/httptest test: 302 to another host, assert the second request has no Authorization header.
