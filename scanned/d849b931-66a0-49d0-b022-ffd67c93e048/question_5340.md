# Q5340: numeric overflow / negative length - existingSkillPrompt in install.go

## Question
Does `existingSkillPrompt` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1089) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1089](pkg/cmd/skills/install/install.go#L1089) - `existingSkillPrompt`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
