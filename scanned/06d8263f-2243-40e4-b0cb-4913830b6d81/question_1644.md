# Q1644: empty/default host fallback - formatRemoteURL in clone.go

## Question
When host resolution fails inside `formatRemoteURL` in [pkg/cmd/gist/clone/clone.go](pkg/cmd/gist/clone/clone.go#L96), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [pkg/cmd/gist/clone/clone.go:96](pkg/cmd/gist/clone/clone.go#L96) - `formatRemoteURL`
- Entrypoint: gh gist clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
