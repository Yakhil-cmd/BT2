# Q5728: cache key omits host or auth identity - AuthFlow in flow.go

## Question
Does the caching in `AuthFlow` in [internal/authflow/flow.go](internal/authflow/flow.go#L30) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [internal/authflow/flow.go:30](internal/authflow/flow.go#L30) - `AuthFlow`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
