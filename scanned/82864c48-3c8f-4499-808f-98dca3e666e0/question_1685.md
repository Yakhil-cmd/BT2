# Q1685: cache key omits host or auth identity - fetchReleaseFromTag in http.go

## Question
Does the caching in `fetchReleaseFromTag` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L147) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/extension/http.go:147](pkg/cmd/extension/http.go#L147) - `fetchReleaseFromTag`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
