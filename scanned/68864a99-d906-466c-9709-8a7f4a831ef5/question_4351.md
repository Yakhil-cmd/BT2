# Q4351: empty/default host fallback - (HelperConfig).ConfigureOurs in helper_config.go

## Question
When host resolution fails inside `ConfigureOurs` in [pkg/cmd/auth/shared/gitcredentials/helper_config.go](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L22), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [pkg/cmd/auth/shared/gitcredentials/helper_config.go:22](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L22) - `(HelperConfig).ConfigureOurs`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
