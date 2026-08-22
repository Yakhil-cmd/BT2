# Q5028: case/Unicode normalization collision - HomeDirPath in config.go

## Question
Can two names differing only in case or Unicode normalization reach `HomeDirPath` in [internal/config/config.go](internal/config/config.go#L702) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [internal/config/config.go:702](internal/config/config.go#L702) - `HomeDirPath`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
