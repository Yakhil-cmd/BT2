# Q5690: agent log stream rendered raw - importRun in import.go

## Question
Is the streamed agent/job log printed by `importRun` in [pkg/cmd/alias/imports/import.go](pkg/cmd/alias/imports/import.go#L94) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/alias/imports/import.go:94](pkg/cmd/alias/imports/import.go#L94) - `importRun`
- Entrypoint: gh alias imports
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
