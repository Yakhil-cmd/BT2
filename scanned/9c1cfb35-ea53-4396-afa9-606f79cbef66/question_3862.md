# Q3862: nil dereference panic on hostile field - Parse in frontmatter.go

## Question
Can an attacker-shaped response make `Parse` in [internal/skills/frontmatter/frontmatter.go](internal/skills/frontmatter/frontmatter.go#L31) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [internal/skills/frontmatter/frontmatter.go:31](internal/skills/frontmatter/frontmatter.go#L31) - `Parse`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
