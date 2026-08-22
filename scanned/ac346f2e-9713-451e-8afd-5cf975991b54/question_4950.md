# Q4950: cache key omits host or auth identity - filterCodespacesByRepoOwner in common.go

## Question
Does the caching in `filterCodespacesByRepoOwner` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L262) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/codespace/common.go:262](pkg/cmd/codespace/common.go#L262) - `filterCodespacesByRepoOwner`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
