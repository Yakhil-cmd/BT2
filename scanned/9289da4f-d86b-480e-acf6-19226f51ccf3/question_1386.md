# Q1386: agent log stream rendered raw - resolveCapiURL in capi.go

## Question
Is the streamed agent/job log printed by `resolveCapiURL` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L48) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:48](pkg/cmd/agent-task/shared/capi.go#L48) - `resolveCapiURL`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
