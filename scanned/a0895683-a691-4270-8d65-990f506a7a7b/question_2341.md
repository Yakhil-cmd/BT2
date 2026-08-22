# Q2341: cache key omits host or auth identity - findForRefs in finder.go

## Question
Does the caching in `findForRefs` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L386) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:386](pkg/cmd/pr/shared/finder.go#L386) - `findForRefs`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
