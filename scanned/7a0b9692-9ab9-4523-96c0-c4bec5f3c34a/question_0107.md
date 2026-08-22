# Q0107: case/Unicode normalization collision - (PathTraversalError).Error in absolute.go

## Question
Can two names differing only in case or Unicode normalization reach `Error` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L72) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [internal/safepaths/absolute.go:72](internal/safepaths/absolute.go#L72) - `(PathTraversalError).Error`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
