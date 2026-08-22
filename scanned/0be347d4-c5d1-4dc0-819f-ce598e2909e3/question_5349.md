# Q5349: nil dereference panic on hostile field - NewCmdUpdate in update.go

## Question
Can an attacker-shaped response make `NewCmdUpdate` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L66) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [pkg/cmd/skills/update/update.go:66](pkg/cmd/skills/update/update.go#L66) - `NewCmdUpdate`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
