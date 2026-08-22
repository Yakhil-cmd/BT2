# Q5533: path traversal in join - (IOStreams).TempFile in iostreams.go

## Question
Can an issue/PR title, body, comment, check output, or release note the attacker authored reaching `TempFile` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L459) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [pkg/iostreams/iostreams.go:459](pkg/iostreams/iostreams.go#L459) - `(IOStreams).TempFile`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh pr view.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
