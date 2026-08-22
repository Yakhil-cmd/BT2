# Q5684: path separator confusion - extractTarGz in copilot.go

## Question
Does `extractTarGz` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L413) treat backslashes in member names as literal characters on Unix and separators on Windows, producing an OS-dependent escape from the destination?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:413](pkg/cmd/copilot/copilot.go#L413) - `extractTarGz`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an entry named `..\..\evil` targeting Windows victims.
- Invariant to test: Member names are normalized to forward slashes and validated identically on all platforms.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Cross-platform test asserting the same rejection for backslash names.
