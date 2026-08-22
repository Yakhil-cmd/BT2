# Q3585: stored token readable by other local surfaces - (cfg).Migrate in config.go

## Question
Does `Migrate` in [internal/config/config.go](internal/config/config.go#L182) place the token somewhere reachable by processes gh itself launches for attacker-published code (extensions, skills, editors, hooks)?

## Target
- File/function: [internal/config/config.go:182](internal/config/config.go#L182) - `(cfg).Migrate`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an extension/skill the victim installs, then read the credential.
- Invariant to test: Tokens live in the keyring or a 0600 file and are not exported to child processes of third-party code.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment omits token variables.
