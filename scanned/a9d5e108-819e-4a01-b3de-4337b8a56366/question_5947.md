# Q5947: nested MkdirAll escape - DiscoverLocalSkillsWithOptions in discovery.go

## Question
Does `DiscoverLocalSkillsWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L974) call MkdirAll on a multi-segment name from a published skill's archive entries, frontmatter, and registry metadata before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [internal/skills/discovery/discovery.go:974](internal/skills/discovery/discovery.go#L974) - `DiscoverLocalSkillsWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
