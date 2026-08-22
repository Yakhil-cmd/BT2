# Q2023: cache key omits host or auth identity - GetCodespaceConnection in codespaces.go

## Question
Does the caching in `GetCodespaceConnection` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L60) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [internal/codespaces/codespaces.go:60](internal/codespaces/codespaces.go#L60) - `GetCodespaceConnection`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
