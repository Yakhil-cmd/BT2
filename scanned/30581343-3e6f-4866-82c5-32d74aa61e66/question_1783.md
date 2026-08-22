# Q1783: nested MkdirAll escape - updateSkillInPlace in update.go

## Question
Does `updateSkillInPlace` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L418) call MkdirAll on a multi-segment name from a published skill's archive entries, frontmatter, and registry metadata before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [pkg/cmd/skills/update/update.go:418](pkg/cmd/skills/update/update.go#L418) - `updateSkillInPlace`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
