# Q2622: case/Unicode normalization collision - (destinationWriter).makePath in download.go

## Question
Can two names differing only in case or Unicode normalization reach `makePath` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L379) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [pkg/cmd/release/download/download.go:379](pkg/cmd/release/download/download.go#L379) - `(destinationWriter).makePath`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
