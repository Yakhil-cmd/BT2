# Q4264: update notice renders remote text - importRun in import.go

## Question
Can the update/release notes rendered by `importRun` in [pkg/cmd/alias/imports/import.go](pkg/cmd/alias/imports/import.go#L94) contain control sequences or a forged instruction line shown after every command?

## Target
- File/function: [pkg/cmd/alias/imports/import.go:94](pkg/cmd/alias/imports/import.go#L94) - `importRun`
- Entrypoint: gh alias imports
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish release notes with escape payloads (or serve them from an attacker-controlled host).
- Invariant to test: Notice text is sanitized and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile release notes.
