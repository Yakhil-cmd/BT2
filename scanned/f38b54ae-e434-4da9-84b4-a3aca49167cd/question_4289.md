# Q4289: empty/default host fallback - (cfg).AccessiblePrompter in config.go

## Question
When host resolution fails inside `AccessiblePrompter` in [internal/config/config.go](internal/config/config.go#L123), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [internal/config/config.go:123](internal/config/config.go#L123) - `(cfg).AccessiblePrompter`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
