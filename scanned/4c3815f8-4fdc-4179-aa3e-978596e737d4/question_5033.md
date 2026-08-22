# Q5033: logout leaves usable credentials - migrateConfig in multi_account.go

## Question
Does `migrateConfig` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L197) leave the token in the keyring, config, or git credential store when part of the removal fails, so a revoked-in-intent credential stays usable?

## Target
- File/function: [internal/config/migration/multi_account.go:197](internal/config/migration/multi_account.go#L197) - `migrateConfig`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Force one removal step to fail during the victim's logout.
- Invariant to test: Logout is all-or-nothing and reports residual credentials.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test injecting a failure in each step asserting either full cleanup or a loud error.
