# Q5995: cache key omits host or auth identity - detectDefaultBranch in publish.go

## Question
Does the caching in `detectDefaultBranch` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L690) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:690](pkg/cmd/skills/publish/publish.go#L690) - `detectDefaultBranch`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
