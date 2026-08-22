# Q5323: numeric overflow / negative length - NewCmdInstall in install.go

## Question
Does `NewCmdInstall` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L76) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/skills/install/install.go:76](pkg/cmd/skills/install/install.go#L76) - `NewCmdInstall`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
