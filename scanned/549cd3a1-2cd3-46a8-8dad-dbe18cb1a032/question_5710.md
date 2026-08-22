# Q5710: case/Unicode normalization collision - setStateEntry in update.go

## Question
Can two names differing only in case or Unicode normalization reach `setStateEntry` in [internal/update/update.go](internal/update/update.go#L162) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [internal/update/update.go:162](internal/update/update.go#L162) - `setStateEntry`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
