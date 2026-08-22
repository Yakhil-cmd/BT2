# Q4599: numeric overflow / negative length - fetchDescription in discovery.go

## Question
Does `fetchDescription` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L648) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [internal/skills/discovery/discovery.go:648](internal/skills/discovery/discovery.go#L648) - `fetchDescription`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
