# Q2322: unauthenticated fallback on error - executeRemoteRepoSync in sync.go

## Question
When authentication fails inside `executeRemoteRepoSync` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L281), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:281](pkg/cmd/repo/sync/sync.go#L281) - `executeRemoteRepoSync`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
