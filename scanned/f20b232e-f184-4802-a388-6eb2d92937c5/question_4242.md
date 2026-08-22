# Q4242: cache key omits host or auth identity - resolveCapiURL in capi.go

## Question
Does the caching in `resolveCapiURL` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L48) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:48](pkg/cmd/agent-task/shared/capi.go#L48) - `resolveCapiURL`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
