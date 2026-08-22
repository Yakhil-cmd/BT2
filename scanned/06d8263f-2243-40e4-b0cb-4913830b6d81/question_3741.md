# Q3741: cache key omits host or auth identity - forkRun in fork.go

## Question
Does the caching in `forkRun` in [pkg/cmd/repo/fork/fork.go](pkg/cmd/repo/fork/fork.go#L159) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/repo/fork/fork.go:159](pkg/cmd/repo/fork/fork.go#L159) - `forkRun`
- Entrypoint: gh repo fork
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
