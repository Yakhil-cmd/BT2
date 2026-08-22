# Q1400: agent log stream rendered raw - fetchExpectedChecksum in copilot.go

## Question
Is the streamed agent/job log printed by `fetchExpectedChecksum` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L342) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:342](pkg/cmd/copilot/copilot.go#L342) - `fetchExpectedChecksum`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
