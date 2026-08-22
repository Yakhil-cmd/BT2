# Q5485: existing files overwritten silently - populateLogSegments in logs.go

## Question
Does `populateLogSegments` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L95) overwrite files already present in the destination when the remote object dictates the name?

## Target
- File/function: [pkg/cmd/run/view/logs.go:95](pkg/cmd/run/view/logs.go#L95) - `populateLogSegments`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Name the asset after a file in the victim's working directory (Makefile, .env, a script).
- Invariant to test: Existing paths are never clobbered without an explicit flag.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with a pre-existing file asserting an error.
