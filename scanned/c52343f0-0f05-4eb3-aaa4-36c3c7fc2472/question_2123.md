# Q2123: update notice renders remote text - ValidAliasNameFunc in validations.go

## Question
Can the update/release notes rendered by `ValidAliasNameFunc` in [pkg/cmd/alias/shared/validations.go](pkg/cmd/alias/shared/validations.go#L15) contain control sequences or a forged instruction line shown after every command?

## Target
- File/function: [pkg/cmd/alias/shared/validations.go:15](pkg/cmd/alias/shared/validations.go#L15) - `ValidAliasNameFunc`
- Entrypoint: gh alias
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish release notes with escape payloads (or serve them from an attacker-controlled host).
- Invariant to test: Notice text is sanitized and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile release notes.
