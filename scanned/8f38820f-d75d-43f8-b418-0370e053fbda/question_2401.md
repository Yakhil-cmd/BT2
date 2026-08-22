# Q2401: case/Unicode normalization collision - makeSymlink in symlink_other.go

## Question
Can two names differing only in case or Unicode normalization reach `makeSymlink` in [pkg/cmd/extension/symlink_other.go](pkg/cmd/extension/symlink_other.go#L7) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [pkg/cmd/extension/symlink_other.go:7](pkg/cmd/extension/symlink_other.go#L7) - `makeSymlink`
- Entrypoint: gh extension symlink
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
