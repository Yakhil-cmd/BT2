# Q5945: cache key omits host or auth identity - FetchBlob in discovery.go

## Question
Does the caching in `FetchBlob` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L918) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [internal/skills/discovery/discovery.go:918](internal/skills/discovery/discovery.go#L918) - `FetchBlob`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
