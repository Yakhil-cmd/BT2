# Q0393: numeric overflow / negative length - stripGitHubMetadata in publish.go

## Question
Does `stripGitHubMetadata` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1143) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1143](pkg/cmd/skills/publish/publish.go#L1143) - `stripGitHubMetadata`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
