# Q2830: duplicate entry overwrite - extractTarGz in copilot.go

## Question
Can duplicate member names in an archive processed by `extractTarGz` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L413) let a second entry silently replace an already-validated first entry?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:413](pkg/cmd/copilot/copilot.go#L413) - `extractTarGz`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an archive where the same path appears twice with different content.
- Invariant to test: Duplicate member names are rejected before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with a duplicated entry asserting an error.
