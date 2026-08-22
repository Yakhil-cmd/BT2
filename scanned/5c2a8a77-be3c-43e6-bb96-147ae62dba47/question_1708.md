# Q1708: empty/default host fallback - mightBeGHESUser in cmd.go

## Question
When host resolution fails inside `mightBeGHESUser` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L482), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [internal/ghcmd/cmd.go:482](internal/ghcmd/cmd.go#L482) - `mightBeGHESUser`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
