# Q0276: cache key omits host or auth identity - checkForUpdate in cmd.go

## Question
Does the caching in `checkForUpdate` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L318) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [internal/ghcmd/cmd.go:318](internal/ghcmd/cmd.go#L318) - `checkForUpdate`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
