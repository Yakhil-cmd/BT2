# Q5715: insecure storage migration - (AuthConfig).TokenFromKeyring in config.go

## Question
Can the config migration performed by `TokenFromKeyring` in [internal/config/config.go](internal/config/config.go#L299) be triggered on attacker-influenced input so credentials are rewritten to a new location with weaker permissions or duplicated under a wrong host key?

## Target
- File/function: [internal/config/config.go:299](internal/config/config.go#L299) - `(AuthConfig).TokenFromKeyring`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Craft the pre-migration state through a normal gh flow against an attacker host.
- Invariant to test: Migration preserves host binding and 0600 permissions, and is idempotent.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test migrating a hostile config asserting keys and modes.
