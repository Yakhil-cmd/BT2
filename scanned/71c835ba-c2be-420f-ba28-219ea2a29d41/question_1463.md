# Q1463: credential helper install widens scope - migrateToken in multi_account.go

## Question
Can `migrateToken` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L188) install or rewrite a git credential helper entry whose URL pattern is broader than the authenticated host (wildcard, scheme-less, or path-less), so unrelated hosts receive the token?

## Target
- File/function: [internal/config/migration/multi_account.go:188](internal/config/migration/multi_account.go#L188) - `migrateToken`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish repos on lookalike hosts that then match the installed helper pattern.
- Invariant to test: Helper entries are written with an exact `https://host` key.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the written gitconfig section key is exactly the authenticated host.
