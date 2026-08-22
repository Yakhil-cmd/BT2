# Q5976: case/Unicode normalization collision - swapDirectoryContents in update.go

## Question
Can two names differing only in case or Unicode normalization reach `swapDirectoryContents` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L470) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [pkg/cmd/skills/update/update.go:470](pkg/cmd/skills/update/update.go#L470) - `swapDirectoryContents`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
