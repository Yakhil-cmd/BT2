# Q3749: submodule fetch leaks credentials - executeLocalRepoSync in sync.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `executeLocalRepoSync` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L221), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:221](pkg/cmd/repo/sync/sync.go#L221) - `executeLocalRepoSync`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
