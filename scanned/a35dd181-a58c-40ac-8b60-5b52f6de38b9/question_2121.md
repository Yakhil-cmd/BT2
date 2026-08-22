# Q2121: alias expansion executes attacker text - NewCmdImport in import.go

## Question
Can data that originated remotely (imported alias file, skill/extension metadata, repository config) reach `NewCmdImport` in [pkg/cmd/alias/imports/import.go](pkg/cmd/alias/imports/import.go#L28) and be expanded into a shell alias that runs on the next gh invocation?

## Target
- File/function: [pkg/cmd/alias/imports/import.go:28](pkg/cmd/alias/imports/import.go#L28) - `NewCmdImport`
- Entrypoint: gh alias imports
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the victim to import an alias set published by the attacker.
- Invariant to test: Shell aliases require explicit interactive confirmation and are never written from remote content.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting an imported alias file cannot create a shell alias without confirmation.
