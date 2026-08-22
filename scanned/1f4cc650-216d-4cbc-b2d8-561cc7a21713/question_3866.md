# Q3866: numeric overflow / negative length - readFrom in lockfile.go

## Question
Does `readFrom` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L53) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:53](internal/skills/lockfile/lockfile.go#L53) - `readFrom`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
