# Q3886: nil dereference panic on hostile field - fetchDescription in discovery.go

## Question
Can an attacker-shaped response make `fetchDescription` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L648) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [internal/skills/discovery/discovery.go:648](internal/skills/discovery/discovery.go#L648) - `fetchDescription`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
