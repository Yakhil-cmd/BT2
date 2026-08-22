# Q0483: cache key omits host or auth identity - NewCmdDownload in download.go

## Question
Does the caching in `NewCmdDownload` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L39) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/run/download/download.go:39](pkg/cmd/run/download/download.go#L39) - `NewCmdDownload`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
