# Q1425: update notice renders remote text - CheckForUpdate in update.go

## Question
Can the update/release notes rendered by `CheckForUpdate` in [internal/update/update.go](internal/update/update.go#L92) contain control sequences or a forged instruction line shown after every command?

## Target
- File/function: [internal/update/update.go:92](internal/update/update.go#L92) - `CheckForUpdate`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish release notes with escape payloads (or serve them from an attacker-controlled host).
- Invariant to test: Notice text is sanitized and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile release notes.
