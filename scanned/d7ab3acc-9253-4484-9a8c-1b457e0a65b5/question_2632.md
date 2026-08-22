# Q2632: path separator confusion - newZipLogMap in logs.go

## Question
Does `newZipLogMap` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L166) treat backslashes in member names as literal characters on Unix and separators on Windows, producing an OS-dependent escape from the destination?

## Target
- File/function: [pkg/cmd/run/view/logs.go:166](pkg/cmd/run/view/logs.go#L166) - `newZipLogMap`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an entry named `..\..\evil` targeting Windows victims.
- Invariant to test: Member names are normalized to forward slashes and validated identically on all platforms.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Cross-platform test asserting the same rejection for backslash names.
