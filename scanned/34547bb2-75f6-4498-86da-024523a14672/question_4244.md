# Q4244: update notice renders remote text - NewCmdCreate in create.go

## Question
Can the update/release notes rendered by `NewCmdCreate` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L49) contain control sequences or a forged instruction line shown after every command?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:49](pkg/cmd/agent-task/create/create.go#L49) - `NewCmdCreate`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish release notes with escape payloads (or serve them from an attacker-controlled host).
- Invariant to test: Notice text is sanitized and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile release notes.
