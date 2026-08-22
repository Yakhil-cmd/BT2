# Q3677: path traversal in join - (PathTraversalError).Error in absolute.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes reaching `Error` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L72) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [internal/safepaths/absolute.go:72](internal/safepaths/absolute.go#L72) - `(PathTraversalError).Error`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh run download.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
