# Q2125: update notice renders remote text - NewCmdSet in set.go

## Question
Can the update/release notes rendered by `NewCmdSet` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L48) contain control sequences or a forged instruction line shown after every command?

## Target
- File/function: [pkg/cmd/secret/set/set.go:48](pkg/cmd/secret/set/set.go#L48) - `NewCmdSet`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish release notes with escape payloads (or serve them from an attacker-controlled host).
- Invariant to test: Notice text is sanitized and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile release notes.
