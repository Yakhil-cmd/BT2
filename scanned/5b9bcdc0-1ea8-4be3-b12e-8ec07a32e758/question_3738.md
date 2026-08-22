# Q3738: unauthenticated fallback on error - cloneRun in clone.go

## Question
When authentication fails inside `cloneRun` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L111), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:111](pkg/cmd/repo/clone/clone.go#L111) - `cloneRun`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
