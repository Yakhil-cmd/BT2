# Q5230: empty/default host fallback - (Manager).goBinScaffolding in manager.go

## Question
When host resolution fails inside `goBinScaffolding` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L670), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [pkg/cmd/extension/manager.go:670](pkg/cmd/extension/manager.go#L670) - `(Manager).goBinScaffolding`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
