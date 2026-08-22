# Q4247: agent log stream rendered raw - fetchJobWithBackoff in create.go

## Question
Is the streamed agent/job log printed by `fetchJobWithBackoff` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L235) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:235](pkg/cmd/agent-task/create/create.go#L235) - `fetchJobWithBackoff`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
