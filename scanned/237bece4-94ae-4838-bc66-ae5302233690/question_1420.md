# Q1420: agent log stream rendered raw - GetSecretApp in shared.go

## Question
Is the streamed agent/job log printed by `GetSecretApp` in [pkg/cmd/secret/shared/shared.go](pkg/cmd/secret/shared/shared.go#L66) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/secret/shared/shared.go:66](pkg/cmd/secret/shared/shared.go#L66) - `GetSecretApp`
- Entrypoint: gh secret
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
