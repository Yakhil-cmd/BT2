# Q3605: stored token readable by other local surfaces - migrateToken in multi_account.go

## Question
Does `migrateToken` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L188) place the token somewhere reachable by processes gh itself launches for attacker-published code (extensions, skills, editors, hooks)?

## Target
- File/function: [internal/config/migration/multi_account.go:188](internal/config/migration/multi_account.go#L188) - `migrateToken`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an extension/skill the victim installs, then read the credential.
- Invariant to test: Tokens live in the keyring or a 0600 file and are not exported to child processes of third-party code.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment omits token variables.
