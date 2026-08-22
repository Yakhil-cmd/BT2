# Q0477: cache key omits host or auth identity - downloadRun in download.go

## Question
Does the caching in `downloadRun` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L142) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/release/download/download.go:142](pkg/cmd/release/download/download.go#L142) - `downloadRun`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
