# Q4790: empty/default host fallback - GetGist in shared.go

## Question
When host resolution fails inside `GetGist` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L64), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:64](pkg/cmd/gist/shared/shared.go#L64) - `GetGist`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
