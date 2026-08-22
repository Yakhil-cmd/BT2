# Q1423: agent log stream rendered raw - (Context).findKeygen in ssh_keys.go

## Question
Is the streamed agent/job log printed by `findKeygen` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L102) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/ssh/ssh_keys.go:102](pkg/ssh/ssh_keys.go#L102) - `(Context).findKeygen`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
