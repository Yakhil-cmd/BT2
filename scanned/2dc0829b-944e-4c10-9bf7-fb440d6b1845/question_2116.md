# Q2116: case/Unicode normalization collision - extractTarGz in copilot.go

## Question
Can two names differing only in case or Unicode normalization reach `extractTarGz` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L413) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:413](pkg/cmd/copilot/copilot.go#L413) - `extractTarGz`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
