# Q1205: path from a repo file listing - getZipLogMap in logs.go

## Question
Can repository file paths returned by the API and used in `getZipLogMap` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L221) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/run/view/logs.go:221](pkg/cmd/run/view/logs.go#L221) - `getZipLogMap`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
