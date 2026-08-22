# Q4283: nil dereference panic on hostile field - getStateEntry in update.go

## Question
Can an attacker-shaped response make `getStateEntry` in [internal/update/update.go](internal/update/update.go#L147) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [internal/update/update.go:147](internal/update/update.go#L147) - `getStateEntry`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
