# Q3914: nil dereference panic on hostile field - existingSkillPrompt in install.go

## Question
Can an attacker-shaped response make `existingSkillPrompt` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1089) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1089](pkg/cmd/skills/install/install.go#L1089) - `existingSkillPrompt`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
