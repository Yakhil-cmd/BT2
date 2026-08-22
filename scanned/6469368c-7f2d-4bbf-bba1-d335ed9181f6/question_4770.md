# Q4770: cache key omits host or auth identity - ListArtifacts in artifacts.go

## Question
Does the caching in `ListArtifacts` in [pkg/cmd/run/shared/artifacts.go](pkg/cmd/run/shared/artifacts.go#L23) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/run/shared/artifacts.go:23](pkg/cmd/run/shared/artifacts.go#L23) - `ListArtifacts`
- Entrypoint: gh run
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
