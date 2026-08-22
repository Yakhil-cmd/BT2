# Q1087: numeric overflow / negative length - NewCmdPublish in publish.go

## Question
Does `NewCmdPublish` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L91) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:91](pkg/cmd/skills/publish/publish.go#L91) - `NewCmdPublish`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
