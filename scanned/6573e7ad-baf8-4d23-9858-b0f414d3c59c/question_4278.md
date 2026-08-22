# Q4278: update notice renders remote text - (Context).GenerateSSHKey in ssh_keys.go

## Question
Can the update/release notes rendered by `GenerateSSHKey` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L51) contain control sequences or a forged instruction line shown after every command?

## Target
- File/function: [pkg/ssh/ssh_keys.go:51](pkg/ssh/ssh_keys.go#L51) - `(Context).GenerateSSHKey`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish release notes with escape payloads (or serve them from an attacker-controlled host).
- Invariant to test: Notice text is sanitized and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile release notes.
