# Q4575: numeric overflow / negative length - Parse in frontmatter.go

## Question
Does `Parse` in [internal/skills/frontmatter/frontmatter.go](internal/skills/frontmatter/frontmatter.go#L31) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [internal/skills/frontmatter/frontmatter.go:31](internal/skills/frontmatter/frontmatter.go#L31) - `Parse`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
