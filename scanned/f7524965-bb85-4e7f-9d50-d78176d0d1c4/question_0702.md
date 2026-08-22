# Q0702: cache key omits host or auth identity - mapRepoNamesToIDs in set.go

## Question
Does the caching in `mapRepoNamesToIDs` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L435) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/secret/set/set.go:435](pkg/cmd/secret/set/set.go#L435) - `mapRepoNamesToIDs`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
