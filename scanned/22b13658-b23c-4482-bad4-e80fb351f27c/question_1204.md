# Q1204: duplicate entry overwrite - newZipLogMap in logs.go

## Question
Can duplicate member names in an archive processed by `newZipLogMap` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L166) let a second entry silently replace an already-validated first entry?

## Target
- File/function: [pkg/cmd/run/view/logs.go:166](pkg/cmd/run/view/logs.go#L166) - `newZipLogMap`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an archive where the same path appears twice with different content.
- Invariant to test: Duplicate member names are rejected before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with a duplicated entry asserting an error.
