# Q5272: case/Unicode normalization collision - checkForUpdate in cmd.go

## Question
Can two names differing only in case or Unicode normalization reach `checkForUpdate` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L318) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [internal/ghcmd/cmd.go:318](internal/ghcmd/cmd.go#L318) - `checkForUpdate`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
