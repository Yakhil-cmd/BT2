# Q3513: cache key omits host or auth identity - newCodeCmd in code.go

## Question
Does the caching in `newCodeCmd` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L11) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/codespace/code.go:11](pkg/cmd/codespace/code.go#L11) - `newCodeCmd`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
