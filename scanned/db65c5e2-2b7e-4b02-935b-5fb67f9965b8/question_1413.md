# Q1413: agent log stream rendered raw - setSecret in set.go

## Question
Is the streamed agent/job log printed by `setSecret` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L330) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/secret/set/set.go:330](pkg/cmd/secret/set/set.go#L330) - `setSecret`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
