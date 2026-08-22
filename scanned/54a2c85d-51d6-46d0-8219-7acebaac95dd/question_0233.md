# Q0233: case/Unicode normalization collision - (Manager).otherBinScaffolding in manager.go

## Question
Can two names differing only in case or Unicode normalization reach `otherBinScaffolding` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L645) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [pkg/cmd/extension/manager.go:645](pkg/cmd/extension/manager.go#L645) - `(Manager).otherBinScaffolding`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
