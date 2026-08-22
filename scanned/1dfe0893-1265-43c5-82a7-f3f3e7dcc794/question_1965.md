# Q1965: case/Unicode normalization collision - (IOStreams).TempFile in iostreams.go

## Question
Can two names differing only in case or Unicode normalization reach `TempFile` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L459) and collide on macOS/Windows so a trusted file is replaced by attacker content?

## Target
- File/function: [pkg/iostreams/iostreams.go:459](pkg/iostreams/iostreams.go#L459) - `(IOStreams).TempFile`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish `Config.yml` alongside `config.yml`, or an NFD variant of an existing name.
- Invariant to test: Collision detection compares case-folded, NFC-normalized names before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with `Config.yml`/`config.yml` and NFC/NFD pairs asserting the second write is rejected.
