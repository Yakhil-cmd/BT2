# Q2634: asset filename controls the write path - getJobNameForLogFilename in logs.go

## Question
Does `getJobNameForLogFilename` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L246) build the output path from a server-supplied name (asset name, artifact name, gist filename, Content-Disposition) without sanitizing separators and traversal?

## Target
- File/function: [pkg/cmd/run/view/logs.go:246](pkg/cmd/run/view/logs.go#L246) - `getJobNameForLogFilename`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a release/artifact/gist whose file is named `../../.bashrc` and let the victim run gh run view.
- Invariant to test: Output names are sanitized to a single path element inside the chosen directory.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile names asserting the resolved output path.
