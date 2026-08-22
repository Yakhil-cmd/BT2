# Q4961: width/emoji handling desync - followLogs in create.go

## Question
Can zero-width, RTL-override, or combining characters in an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes rendered by `followLogs` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L263) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:263](pkg/cmd/agent-task/create/create.go#L263) - `followLogs`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
