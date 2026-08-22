# Q1417: cache key omits host or auth identity - getPubKey in http.go

## Question
Does the caching in `getPubKey` in [pkg/cmd/secret/set/http.go](pkg/cmd/secret/set/http.go#L34) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/secret/set/http.go:34](pkg/cmd/secret/set/http.go#L34) - `getPubKey`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
