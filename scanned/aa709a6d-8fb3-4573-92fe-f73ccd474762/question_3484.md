# Q3484: cache key omits host or auth identity - (API).GetCodespacesPermissionsCheck in api.go

## Question
Does the caching in `GetCodespacesPermissionsCheck` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L704) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [internal/codespaces/api/api.go:704](internal/codespaces/api/api.go#L704) - `(API).GetCodespacesPermissionsCheck`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
