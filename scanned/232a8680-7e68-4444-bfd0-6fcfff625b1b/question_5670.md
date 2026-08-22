# Q5670: agent log stream rendered raw - NewCmdCreate in create.go

## Question
Is the streamed agent/job log printed by `NewCmdCreate` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L49) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:49](pkg/cmd/agent-task/create/create.go#L49) - `NewCmdCreate`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
