# Q5707: alias expansion executes attacker text - CheckForUpdate in update.go

## Question
Can data that originated remotely (imported alias file, skill/extension metadata, repository config) reach `CheckForUpdate` in [internal/update/update.go](internal/update/update.go#L92) and be expanded into a shell alias that runs on the next gh invocation?

## Target
- File/function: [internal/update/update.go:92](internal/update/update.go#L92) - `CheckForUpdate`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the victim to import an alias set published by the attacker.
- Invariant to test: Shell aliases require explicit interactive confirmation and are never written from remote content.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting an imported alias file cannot create a shell alias without confirmation.
