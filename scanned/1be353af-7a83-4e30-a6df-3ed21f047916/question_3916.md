# Q3916: case/Unicode normalization collision - printFileTree in install.go

## Question
Can two names differing only in case or Unicode normalization reach `printFileTree` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1151) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1151](pkg/cmd/skills/install/install.go#L1151) - `printFileTree`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
