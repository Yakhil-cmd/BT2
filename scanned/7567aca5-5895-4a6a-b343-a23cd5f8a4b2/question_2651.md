# Q2651: empty/default host fallback - ListGists in shared.go

## Question
When host resolution fails inside `ListGists` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L103), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:103](pkg/cmd/gist/shared/shared.go#L103) - `ListGists`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
