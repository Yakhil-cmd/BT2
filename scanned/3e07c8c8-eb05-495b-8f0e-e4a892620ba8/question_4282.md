# Q4282: agent log stream rendered raw - getLatestReleaseInfo in update.go

## Question
Is the streamed agent/job log printed by `getLatestReleaseInfo` in [internal/update/update.go](internal/update/update.go#L115) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [internal/update/update.go:115](internal/update/update.go#L115) - `getLatestReleaseInfo`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
