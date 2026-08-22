# Q3370: empty/default host fallback - updateGist in edit.go

## Question
When host resolution fails inside `updateGist` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L399), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:399](pkg/cmd/gist/edit/edit.go#L399) - `updateGist`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
