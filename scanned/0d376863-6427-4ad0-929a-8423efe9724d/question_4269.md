# Q4269: alias expansion executes attacker text - setSecret in set.go

## Question
Can data that originated remotely (imported alias file, skill/extension metadata, repository config) reach `setSecret` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L330) and be expanded into a shell alias that runs on the next gh invocation?

## Target
- File/function: [pkg/cmd/secret/set/set.go:330](pkg/cmd/secret/set/set.go#L330) - `setSecret`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the victim to import an alias set published by the attacker.
- Invariant to test: Shell aliases require explicit interactive confirmation and are never written from remote content.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting an imported alias file cannot create a shell alias without confirmation.
