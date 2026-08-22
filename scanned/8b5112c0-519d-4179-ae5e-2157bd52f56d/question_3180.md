# Q3180: case/Unicode normalization collision - DiscoverLocalSkillsWithOptions in discovery.go

## Question
Can two names differing only in case or Unicode normalization reach `DiscoverLocalSkillsWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L974) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [internal/skills/discovery/discovery.go:974](internal/skills/discovery/discovery.go#L974) - `DiscoverLocalSkillsWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
