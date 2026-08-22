# Q4304: scope elevation without user consent - (AuthConfig).TokenFromKeyring in config.go

## Question
Can the flow in `TokenFromKeyring` in [internal/config/config.go](internal/config/config.go#L299) request or persist a broader OAuth scope set than the user approved for the operation actually being run?

## Target
- File/function: [internal/config/config.go:299](internal/config/config.go#L299) - `(AuthConfig).TokenFromKeyring`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Trigger a path that silently refreshes with extra scopes while the user believes they authorized a read-only action.
- Invariant to test: Scope requests match the operation and are shown before authorization.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the scope list sent equals the minimum for the command.
