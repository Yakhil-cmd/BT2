# Q2133: alias expansion executes attacker text - GetSecretEntity in shared.go

## Question
Can data that originated remotely (imported alias file, skill/extension metadata, repository config) reach `GetSecretEntity` in [pkg/cmd/secret/shared/shared.go](pkg/cmd/secret/shared/shared.go#L46) and be expanded into a shell alias that runs on the next gh invocation?

## Target
- File/function: [pkg/cmd/secret/shared/shared.go:46](pkg/cmd/secret/shared/shared.go#L46) - `GetSecretEntity`
- Entrypoint: gh secret
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the victim to import an alias set published by the attacker.
- Invariant to test: Shell aliases require explicit interactive confirmation and are never written from remote content.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting an imported alias file cannot create a shell alias without confirmation.
