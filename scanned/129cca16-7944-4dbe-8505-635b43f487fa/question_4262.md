# Q4262: agent log stream rendered raw - setRun in set.go

## Question
Is the streamed agent/job log printed by `setRun` in [pkg/cmd/alias/set/set.go](pkg/cmd/alias/set/set.go#L95) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/alias/set/set.go:95](pkg/cmd/alias/set/set.go#L95) - `setRun`
- Entrypoint: gh alias set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
