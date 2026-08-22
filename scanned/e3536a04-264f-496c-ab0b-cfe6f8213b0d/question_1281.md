# Q1281: cache key omits host or auth identity - printHumanIssuePreview in view.go

## Question
Does the caching in `printHumanIssuePreview` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L240) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/issue/view/view.go:240](pkg/cmd/issue/view/view.go#L240) - `printHumanIssuePreview`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
